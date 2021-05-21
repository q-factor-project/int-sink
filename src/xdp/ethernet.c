// Parent header
#include "process.h"

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/endian.h"
#include "helpers/memory.h"

#include "meta.h"

static __u32 packet_pop_eth(struct xdp_md *ctx, struct ethhdr *eth);
static __u32 packet_push_eth(struct xdp_md *ctx, struct ethhdr *eth);

__u32 process_ether(struct xdp_md *ctx)
{
    struct ethhdr eth;
    __u32 result;
    
    result = packet_pop_eth(ctx, &eth);
    if (result)
        return result;

    switch (ntohs(eth.h_proto)) {
    case ETH_P_IP:
        result = process_ipv4(ctx);
        break;
    default:
        result = NONFATAL_ERR;
    }

    switch (result) {
    case NO_ERR:
        return packet_push_eth(ctx, &eth);
    case NONFATAL_ERR:
        result = packet_push_eth(ctx, &eth);
        if (result)
            return result;
        return NONFATAL_ERR;
        break;
    default:
        return result;
    }
}

static __u32 packet_pop_eth(struct xdp_md *ctx, struct ethhdr *eth)
{
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    struct ethhdr *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    if ( ( pkt + 1 ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    memcpy(eth, pkt, sizeof(*eth)); 

    // Shrink packet
    if (bpf_xdp_adjust_head(ctx, sizeof(*eth)))
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_push_eth(struct xdp_md *ctx, struct ethhdr *eth)
{
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -(int)(sizeof(*eth))))
        return FATAL_ERR;
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    struct ethhdr *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Safety check
    if ( ( pkt + 1 ) > end)
        return FATAL_ERR;
    
    // Copy from buffer to packet
    memcpy(pkt, eth, sizeof(*eth));

    return NO_ERR;
}