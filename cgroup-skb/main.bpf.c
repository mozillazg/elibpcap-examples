// go:build ignore
//  +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
     return data != data_end && _skb == __skb && __skb == ___skb;
}

SEC("cgroup_skb/egress")
int sample_prog(struct __sk_buff *skb){
	void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        goto out;
    }

    bpf_printk("Hello from cgroup_skb/egress after pcap filter");
out:
    return 1;
}

char _license[] SEC("license") = "GPL";
