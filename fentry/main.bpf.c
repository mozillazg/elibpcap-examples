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

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(sample_prog, struct sk_buff *skb){
    void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, network_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        goto out;
    }

    bpf_printk("Hello from fentry/__dev_queue_xmit after pcap filter");
out:
    return 0;
}

char _license[] SEC("license") = "GPL";
