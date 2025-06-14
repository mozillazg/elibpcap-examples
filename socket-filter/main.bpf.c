// go:build ignore
//  +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14                                        /* Total octets in header.	 */



static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
     return data != data_end && _skb == __skb && __skb == ___skb;
}

SEC("socket")
int sample_prog(struct __sk_buff *skb){

    void *data = (void *)(long)skb;
    char dummy[1];
    bpf_skb_load_bytes(skb, 0, &dummy, sizeof(dummy));
    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, (void *)data, (void *)dummy)) {
        goto out;
    }

    bpf_printk("Hello from socket filter after pcap filter\n");
out:
    return 0;
}


char _license[] SEC("license") = "GPL";
