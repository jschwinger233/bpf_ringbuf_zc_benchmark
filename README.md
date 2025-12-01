# bpf_ringbuf_zc_benchmark

Micro-benchmark comparing the current ringbuf read path in `cilium/ebpf` (copying into a user buffer) against a proposed zero-copy view API. The BPF program emits skb metadata into a large ring buffer; user space loads the program and repeatedly drains the buffer using either approach.

## Prerequisites
- Go 1.24+ (matches `go.mod`).
- Clang/LLVM (for `go generate ./bpf` if you need to recompile the BPF object).
- Linux kernel with BPF ring buffer support (5.8+) and permission to load BPF programs (root or `CAP_BPF`/`CAP_PERFMON`).
- A fork of `github.com/cilium/ebpf` that contains the zero-copy ringbuf API prototype (see https://github.com/jschwinger233/ebpf/pull/1). Point the `replace` directive in `go.mod` at your local checkout, e.g.

  ```
  replace github.com/cilium/ebpf => /path/to/your/ebpf
  ```

## Build
1) (Optional) Regenerate the eBPF object after changing `bpf/test.c`:
   ```
   go generate ./bpf
   ```
2) Build the benchmark binary:
   ```
   go build
   ```

## Running
Key flags:
- `-n` number of ringbuf events to produce (default 50,000).
- `-mode` `copy|view|both` to choose the code path under test (default `both`).
- `-read-timeout` per-read timeout while waiting for ringbuf data.

Example run pinned to CPU 2 for stability:

```
sudo taskset -c 2 ./bpf_ringbuf_zc_benchmark -n 1999999 -read-timeout 0ms -mode both
```

Sample output (from the numbers in `perf.data`):

```
read-into (copy):     1999999 events in 47.518618ms (42.09 Mevents/s), checksum=9992853683739462143
read-view (zero-copy): 1999999 events in 41.877471ms (47.76 Mevents/s), checksum=9992853672987467519
```

In this run the zero-copy API improved throughput from 42.09 to 47.76 Mevents/s (~13.4%). Absolute numbers depend on CPU pinning, IRQ noise, and ring size (`meta_ringbuf` is 512 MiB by default).

## How it works
- `bpf/test.c` (section `tc`) writes a fixed skb metadata struct into a ring buffer sized at `1<<29` bytes.
- `main.go` loads the object, executes the BPF program with `Program.Run` to generate `-n` events, then drains the ring buffer either via `Reader.ReadInto` (copy) or `Reader.PeekInto` + `Consume` (view / zero-copy).
- Checksums over the struct fields ensure both paths observe identical data.
