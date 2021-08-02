#include "process.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <helpers/memory.h>

#include <types/redirect_info.h>
#include <linux/if_ether.h>

int failed_redirect = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct redirect_info);
    __uint(max_entries, 1);
} redirect_info_arr SEC(".maps");

/*
 * Entry point into xdp program.
 */
SEC("xdp")
int redirect(struct xdp_md *ctx)
{
    __u32 result;
    __u32 key = 0;
    void * pkt;
    void * data_end;
    struct redirect_info *redirect_info;

    result = driver(ctx);

    switch(result) {
    case XDP_PASS:// INT PACKET
        goto KEEP_PACKET;
    case XDP_DROP://FATAL ERROR, SHOULD DROP
    default:
        goto DROP_PACKET;
    }
KEEP_PACKET:
    pkt = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if(pkt + sizeof(struct ethhdr) > data_end)
        goto REDIRECT_FAIL;
    
    if( !(redirect_info = bpf_map_lookup_elem(&redirect_info_arr, &key)) )
        goto REDIRECT_FAIL;

    memcpy(pkt, redirect_info, 12);

    if (bpf_redirect(redirect_info->ifindex, 0))
        return XDP_REDIRECT;
REDIRECT_FAIL:
    failed_redirect++;
DROP_PACKET:
    return XDP_DROP;
}