// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct parameters {
	u16 data_size;
};

volatile const struct parameters PARAM = {};

struct event {
	u64 skb;
	u8 data[0];
};

const struct event *_ __attribute__((unused));

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<30); // 1GB
} meta_ringbuf SEC(".maps");

SEC("tc")
int test(struct __sk_buff *skb)
{
	struct event *event = (struct event *)bpf_ringbuf_reserve(&meta_ringbuf,
								  sizeof(struct event) + PARAM.data_size,
								  0);
	if (!event)
		return 0;

	event->skb = (u64)skb;
	bpf_skb_load_bytes(skb, 0, event->data, PARAM.data_size);

	bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
	return 0;
}
