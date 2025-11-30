// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct skb_meta {
	__u64	address;

	/* fetch 13 fields from skb */
	__u32	len;
	__u32	pkt_type;
	__u32	mark;
	__u32	queue_mapping;
	__u32	protocol;
	__u32	vlan_present;
	__u32	vlan_tci;
	__u32	vlan_proto;
	__u32	priority;
	__u32	ingress_ifindex;
	__u32	ifindex;
	__u32	tc_index;
	__u32	cb[5];
};

const struct skb_meta *_ __attribute__((unused));

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<29);
} meta_ringbuf SEC(".maps");

SEC("tc")
int test(struct __sk_buff *skb)
{
	struct skb_meta *meta = (struct skb_meta *)bpf_ringbuf_reserve(&meta_ringbuf, sizeof(struct skb_meta), 0);
	if (!meta)
		return 0;

	meta->address = (u64)skb;
	meta->len = skb->len;
	meta->pkt_type = skb->pkt_type;
	meta->mark = skb->mark;
	meta->queue_mapping = skb->queue_mapping;
	meta->protocol = skb->protocol;
	meta->vlan_present = skb->vlan_present;
	meta->vlan_tci = skb->vlan_tci;
	meta->vlan_proto = skb->vlan_proto;
	meta->priority = skb->priority;
	meta->ingress_ifindex = skb->ingress_ifindex;
	meta->ifindex = skb->ifindex;
	meta->tc_index = skb->tc_index;
	meta->cb[0] = skb->cb[0];
	meta->cb[1] = skb->cb[1];
	meta->cb[2] = skb->cb[2];
	meta->cb[3] = skb->cb[3];
	meta->cb[4] = skb->cb[4];

	bpf_ringbuf_submit(meta, BPF_RB_NO_WAKEUP);
	return 0;
}
