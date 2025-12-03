# bpf_ringbuf_zc_benchmark

Micro-benchmark that compares two ring buffer read paths in `cilium/ebpf`:

- **copy**: `ringbuf.Reader.ReadInto` copies each record into a user buffer.
- **zero-copy view**: `ringbuf.Reader.PeekInto` returns a view which is consumed with `Reader.Consume`.

The BPF program in `bpf/test.c` writes `struct event { u64 skb; u8 data[]; }` into a 1 GiB ring buffer. User space calls `Program.Run` once per benchmark to generate a full ring of events, then drains it with the selected path.

## Prerequisites
- Go 1.24+.
- Clang/LLVM (only needed if you recompile the BPF object via `go generate`).
- Linux kernel 5.8+ with BPF ring buffer support and permission to load BPF (`root` or `CAP_BPF`/`CAP_PERFMON`).
- At least 1 GiB of locked memory for the ring buffer map. If you see `memlock`/`EPERM`, run `ulimit -l unlimited` or execute the binary with `sudo`.
- A build of `github.com/cilium/ebpf` that includes the zero-copy ringbuf API. Point the `replace` directive in `go.mod` at your local checkout (e.g. `replace github.com/cilium/ebpf => /path/to/ebpf`).

## Build
1) (Optional) Regenerate the BPF object after editing `bpf/test.c`:

   ```bash
   go generate ./bpf
   ```

2) Build the benchmark:

   ```bash
   go build
   ```

The binary is `./bpf_ringbuf_zc_benchmark`.

## Benchmark knobs
- **Ring buffer size**: 1<<30 bytes (set in `bpf/test.c`). This memory is charged against your memlock limit.
- **`-event-size`** *(bytes, default 128)*: total size of each record emitted by BPF, including the 8-byte `skb` field. Payload bytes = `event-size - 8`.
- **`-mode`** *(copy|view|both, default both)*: choose which user-space path to run.
- **Event count per run**: derived from the ring size, not a flag. The program computes

  `events = ring_size / (align(event_size, 8) + ring_header)`

  where `ring_header` is 8 bytes. Examples:
  - 128 B events -> ~7.9 M records per run.
  - 512 B events -> ~2.1 M records per run.
  - 2048 B events -> ~0.52 M records per run.

The benchmark fills the ring once (via `Program.Run`) and immediately drains it, printing throughput and a checksum for each path.

## Running
For stable numbers pin to one CPU and run as root/capable user:

```bash
sudo taskset -c 2 ./bpf_ringbuf_zc_benchmark -mode both -event-size 128
```

To sweep payload sizes (this produced `result.txt`):

```bash
for i in {5..128}; do
  bytes=$((i * 16))
  echo "${bytes} bytes"
  sudo taskset -c 2 ./bpf_ringbuf_zc_benchmark -mode both -event-size "$bytes"
done > result.txt
```

No network attachment is required; the program uses `BPF_PROG_TEST_RUN` via `Program.Run` with the synthetic packet blob provided by user space.

## Latest results (from `result.txt`)
Single-core run on CPU 2, ring size 1 GiB, Go 1.24.4. Throughput is in million events/second (Mev/s); "speedup" is zero-copy / copy.

| event-size (B) | events/run | copy (Mev/s) | zero-copy (Mev/s) | speedup |
| --- | --- | --- | --- | --- |
| 128 | 7,895,160 | 45.63 | 49.83 | 1.09x |
| 512 | 2,064,888 | 25.03 | 34.94 | 1.40x |
| 1024 | 1,040,447 | 8.90 | 34.94 | 3.93x |
| 2048 | 522,247 | 4.57 | 29.56 | 6.47x |

Observations from the full sweep (80 B-2 KiB payloads):
- Minimum speedup was ~1.07x (at 144 B records); maximum was 6.47x (at 2048 B).
- Average speedup across all sizes: ~3.5x.
- Zero-copy advantage grows with larger records because copy throughput falls while view throughput stays roughly flat.

Use `-mode view` or `-mode copy` if you only need one path. The printed checksums should match between modes; a mismatch indicates data corruption.
