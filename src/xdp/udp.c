#include "process.h"

#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/endian.h"
#include "helpers/memory.h"

#include "meta.h"

static __u32 packet_pop_udp(struct xdp_md *ctx, struct udphdr *udp);
static __u32 packet_push_udp(struct xdp_md *ctx, struct udphdr *udp);

__u32 process_udp(struct xdp_md *ctx)
{
    struct udphdr udp;
    __u32 result;

    result = packet_pop_udp(ctx, &udp);
    if (result) // If fail to pop from packet, packet can still be recovered
        return result;

    result = process_int(ctx);

    switch(result) {
    case NO_ERR:
        return packet_push_udp(ctx, &udp);
        break;
    case NONFATAL_ERR:
        result = packet_push_udp(ctx, &udp);
        if (result)
            return result;
        return NONFATAL_ERR;
        break;
    default:
        return result;
    }
}

/*
 * Parses and pops header from packet.
 */
static __u32 packet_pop_udp(struct xdp_md *ctx, struct udphdr *udp)
{
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    if ( ( pkt + sizeof(*udp) ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    memcpy(udp, pkt, sizeof(*udp)); 

    // Shrink packet
    if (bpf_xdp_adjust_head(ctx, sizeof(*udp)))
        return FATAL_ERR;

    return NO_ERR;
}

/*
 * Pushes header from buffer to packet.
 */
static __u32 packet_push_udp(struct xdp_md *ctx, struct udphdr *udp)
{
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -(int)(sizeof(*udp))))
        return FATAL_ERR;

    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    // Update from meta
    udp->check = 0;
    udp->len = htons(ntohs(udp->len) + meta->size_delta);

    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Safety check
    if ( ( pkt + sizeof(*udp) ) > end)
        return FATAL_ERR;
    
    // Copy from buffer to packet
    memcpy(pkt, udp, sizeof(*udp));

    return NO_ERR;
}

