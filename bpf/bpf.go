package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta Test ./test.c -- -I./headers -I. -Wall

func LoadProgram() *TestObjects {
	obj := &TestObjects{}
	if err := LoadTestObjects(obj, nil); err != nil {
		panic(err)
	}
	return obj
}
