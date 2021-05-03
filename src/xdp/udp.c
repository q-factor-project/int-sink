#include "process.h"

#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/endian.h"
#include "helpers/memory.h"
#include "meta.h"

// static __u32 parse_udphdr(struct xdp_md *ctx); Redundant
static __u32 packet_pop_udp(struct xdp_md *ctx, struct udphdr *udp);
static __u32 packet_push_udp(struct xdp_md *ctx, struct udphdr *udp);
static void udp_update_check(struct udphdr *udphdr, __u16 delta);
static void udp_update_length(struct udphdr *udphdr, __u16 delta);

__u32 process_udp(struct xdp_md *ctx)
{
    struct udphdr udp;
    __u32 result;

    result = packet_pop_udp(ctx, &udp);
    if (result) // If fail to pop from packet, packet can still be recovered
        return result;

    result = process_int(ctx);

    __u64 long_result;
    union meta_info info;

    switch(result) {
    case NO_ERR:
        long_result = meta_peek(ctx);

        info.combined_data = long_result;

        if (long_result >> 32 == 0) //If meta valid, adjust header
        {
            udp_update_check(&udp, info.data.csum_delta);
            udp_update_length(&udp, info.data.size_delta);
        }
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
    if (bpf_xdp_adjust_head(ctx, sizeof(udp)))
        return FATAL_ERR;

    return NO_ERR;
}

/*
 * Pushes header from buffer to packet.
 */
static __u32 packet_push_udp(struct xdp_md *ctx, struct udphdr *udp)
{
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, (int)(-sizeof(udp))))
        return FATAL_ERR;


    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Safety check
    if ( ( pkt + sizeof(*udp) ) > end)
        return FATAL_ERR;
    
    // Copy from buffer to packet
    memcpy(pkt, udp, sizeof(*udp));

    return NO_ERR;
}

static void udp_update_length(struct udphdr *udphdr, __u16 delta)
{
    udphdr->len = htons(ntohs(udphdr->len) + delta);
    udp_update_check(udphdr, delta); // Update for change in udp header
    udp_update_check(udphdr, delta); // Update for change in ip pseudo header
}

static void udp_update_check(struct udphdr *udphdr, __u16 delta)
{
    if(udphdr->check)
    {
        __wsum sum;
        sum = udphdr->check;
        sum = htons(ntohs(sum) - delta);
        sum = (sum & 0xFFFF) + (sum >> 16);
        udphdr->check = (sum & 0xFFFF) + (sum >> 16);
    }
}
