module github.com/jschwinger233/bpf_ringbuf_zc_benchmark

go 1.24.4

require github.com/cilium/ebpf v0.20.0

require golang.org/x/sys v0.37.0 // indirect

replace github.com/cilium/ebpf => github.com/jschwinger233/ebpf v0.9.2-0.20251130093829-0236b1f2b7d9
