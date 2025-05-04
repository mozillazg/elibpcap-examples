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

SEC("xdp")
int sample_prog(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (!pcap_filter((void *)ctx, (void *)ctx, (void *)ctx, data, data_end)) {
        goto out;
    }

    bpf_printk("Hello from xdp after pcap filter\n");
out:
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
