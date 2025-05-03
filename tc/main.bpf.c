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

SEC("tc")
int sample_prog(struct __sk_buff *skb){
    bpf_skb_pull_data(skb, 0);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        bpf_printk("pcap_filter not match\n");
        goto out;
    }

    bpf_printk("Hello from tc after pcap filter\n");
out:
    return TC_ACT_UNSPEC;
}


char _license[] SEC("license") = "GPL";
