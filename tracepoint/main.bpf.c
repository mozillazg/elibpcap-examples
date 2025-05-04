// go:build ignore
//  +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1

struct netif_receive_skb_ctx {
    struct trace_entry ent;
    struct sk_buff *skb;
};

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
     return data != data_end && _skb == __skb && __skb == ___skb;
}

SEC("tracepoint/net/netif_receive_skb")
int sample_prog(struct netif_receive_skb_ctx *ctx){
    struct sk_buff *skb = ctx->skb;
    void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, mac_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        goto out;
    }

    bpf_printk("Hello from tracepoint/net/netif_receive_skb after pcap filter");
out:
    return 0;
}

char _license[] SEC("license") = "GPL";
