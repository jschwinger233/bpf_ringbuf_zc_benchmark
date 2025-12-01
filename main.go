package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/jschwinger233/bpf_ringbuf_zc_benchmark/bpf"
)

const (
	defaultEvents  = 50_000
	readTimeout    = 5 * time.Millisecond
	packetDataSize = 128
	ringHeaderSize = 8 // sizeof(struct bpf_ringbuf_hdr)
	recordAlign    = 8 // ringbuf records are 8-byte aligned
)

type skbMeta = bpf.TestSkbMeta

const metaSize = int(unsafe.Sizeof(skbMeta{}))

func main() {
	events := flag.Int("n", defaultEvents, "number of ringbuf events to generate and parse")
	timeout := flag.Duration("read-timeout", readTimeout, "per-read timeout when waiting for ringbuf data")
	mode := flag.String("mode", "both", "benchmark mode: copy | view | both")
	flag.Parse()

	if *events <= 0 {
		log.Fatalf("event count must be > 0 (got %d)", *events)
	}

	obj := bpf.LoadProgram()
	defer obj.Close()

	reader, err := ringbuf.NewReader(obj.MetaRingbuf)
	if err != nil {
		log.Fatalf("create ringbuf reader: %v", err)
	}
	defer reader.Close()

	recordBytes := aligned(metaSize, recordAlign) + ringHeaderSize
	totalBytes := *events * recordBytes
	if totalBytes > reader.BufferSize() {
		log.Fatalf("ringbuf too small: need %d bytes (%d events * %d bytes) but buffer has %d bytes",
			totalBytes, *events, recordBytes, reader.BufferSize())
	}

	packet := make([]byte, packetDataSize)

	runCopy := *mode == "copy" || *mode == "both"
	runView := *mode == "view" || *mode == "both"

	if !runCopy && !runView {
		log.Fatalf("invalid -mode %q (must be copy | view | both)", *mode)
	}

	if runCopy {
		copyDur, copyCount, copyChecksum, err := benchmark("read-into (copy)", reader, obj.Test, packet, *events, *timeout, consumeRingbufCopy)
		if err != nil {
			log.Fatalf("copy benchmark: %v", err)
		}
		fmt.Printf("read-into (copy):     %d events in %s (%.2f Mevents/s), checksum=%d\n",
			copyCount, copyDur, float64(copyCount)/copyDur.Seconds()/1e6, copyChecksum)
	}

	if runView {
		zeroDur, zeroCount, zeroChecksum, err := benchmark("read-view (zero-copy)", reader, obj.Test, packet, *events, *timeout, consumeRingbufView)
		if err != nil {
			log.Fatalf("zero-copy benchmark: %v", err)
		}
		fmt.Printf("read-view (zero-copy): %d events in %s (%.2f Mevents/s), checksum=%d\n",
			zeroCount, zeroDur, float64(zeroCount)/zeroDur.Seconds()/1e6, zeroChecksum)
	}
}

func benchmark(name string, reader *ringbuf.Reader, prog *ebpf.Program, packet []byte, events int, timeout time.Duration, consume func(*ringbuf.Reader, int, time.Duration) (int, uint64, error)) (time.Duration, int, uint64, error) {
	if err := runBatch(prog, packet, events); err != nil {
		return 0, 0, 0, fmt.Errorf("%s: run bpf: %w", name, err)
	}

	reader.SetDeadline(time.Time{}) // clear any previous deadline
	start := time.Now()
	count, checksum, err := consume(reader, events, timeout)
	return time.Since(start), count, checksum, err
}

func runBatch(prog *ebpf.Program, packet []byte, repeat int) error {
	if prog == nil {
		return fmt.Errorf("nil ebpf program")
	}
	if repeat <= 0 {
		return fmt.Errorf("repeat must be positive (got %d)", repeat)
	}
	if repeat > int(^uint32(0)) {
		return fmt.Errorf("repeat too large for kernel test run: %d", repeat)
	}

	_, err := prog.Run(&ebpf.RunOptions{
		Data:   packet,
		Repeat: uint32(repeat),
	})
	return err
}

func consumeRingbufCopy(reader *ringbuf.Reader, expected int, timeout time.Duration) (int, uint64, error) {
	if reader == nil {
		return 0, 0, fmt.Errorf("nil ringbuf reader")
	}

	var rec ringbuf.Record
	var count int
	var checksum uint64

	for count < expected {
		if rec.Remaining <= 0 {
			reader.SetDeadline(time.Now().Add(timeout))
		}

		if err := reader.ReadInto(&rec); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return count, checksum, fmt.Errorf("timeout waiting for events: received %d/%d", count, expected)
			}
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed) {
				continue
			}
			return count, checksum, fmt.Errorf("ringbuf read: %w", err)
		}

		if len(rec.RawSample) != metaSize {
			return count, checksum, fmt.Errorf("short sample: got %d bytes, expected at least %d", len(rec.RawSample), metaSize)
		}

		meta := (*skbMeta)(unsafe.Pointer(&rec.RawSample[0]))
		checksum += sumMeta(meta)
		count++
	}

	return count, checksum, nil
}

func consumeRingbufView(reader *ringbuf.Reader, expected int, timeout time.Duration) (int, uint64, error) {
	if reader == nil {
		return 0, 0, fmt.Errorf("nil ringbuf reader")
	}

	var view ringbuf.View
	var count int
	var checksum uint64

	for count < expected {
		if view.Remaining <= 0 {
			reader.SetDeadline(time.Now().Add(5 * time.Millisecond))
		}

		if err := reader.PeekInto(&view); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return count, checksum, fmt.Errorf("timeout waiting for events: received %d/%d", count, expected)
			}
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed) {
				continue
			}
			return count, checksum, fmt.Errorf("ringbuf read view: %w", err)
		}

		if len(view.Sample) != metaSize {
			reader.Consume(&view)

			return count, checksum, fmt.Errorf("short sample: got %d bytes, expected at least %d", len(view.Sample), metaSize)
		}

		meta := (*skbMeta)(unsafe.Pointer(&view.Sample[0]))
		checksum += sumMeta(meta)
		count++

		reader.Consume(&view)
	}

	return count, checksum, nil
}

func sumMeta(m *skbMeta) uint64 {
	var s uint64
	s += uint64(m.Address)
	s += uint64(m.Len)
	s += uint64(m.PktType)
	s += uint64(m.Mark)
	s += uint64(m.QueueMapping)
	s += uint64(m.Protocol)
	s += uint64(m.VlanPresent)
	s += uint64(m.VlanTci)
	s += uint64(m.VlanProto)
	s += uint64(m.Priority)
	s += uint64(m.IngressIfindex)
	s += uint64(m.Ifindex)
	s += uint64(m.TcIndex)
	for _, cb := range m.Cb {
		s += uint64(cb)
	}
	return s
}

func aligned(n, alignment int) int {
	return (n + alignment - 1) & ^(alignment - 1)
}
