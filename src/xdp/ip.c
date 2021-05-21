#include "process.h"

#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/memory.h"
#include "helpers/endian.h"

#include "meta.h"

#define DSCP_INT 0x17

struct raw_ip { // Buffer for ip data
    struct iphdr ip_hdr;
    __u8 options[MAX_IPOPTLEN];
};

static __u32 packet_pop_ip(struct xdp_md *ctx, struct raw_ip *buffer);
static __u32 packet_push_ip(struct xdp_md *ctx, struct raw_ip *buffer);
static void ip_update_length(struct iphdr *ip, __u16 delta);
static void ip_update_tos(struct iphdr *ip, __u8 new_tos);

__u32 process_ipv4(struct xdp_md *ctx)
{
    struct raw_ip ip;
    memset(&ip, 0, sizeof(ip));
    __u32 result = packet_pop_ip(ctx, &ip);

    if (result)
        return result;

    // Replace with decision function
    switch (ip.ip_hdr.protocol) {
    case 0x06: // TCP Next Header
        result = process_tcp(ctx);
        break;
    case 0x11: // UDP Next Header
        result = process_udp(ctx);
        break;
    default:
        result = NONFATAL_ERR;
        break;
    }

    switch(result)
    {
    case NO_ERR:
        return packet_push_ip(ctx, &ip);
        break;
    case NONFATAL_ERR:
        result = packet_push_ip(ctx, &ip);
        if (result)
            return result;
        return NONFATAL_ERR;
        break;
    default:
        return result;
    }
}

static __u32 packet_pop_ip(struct xdp_md *ctx, struct raw_ip *buffer)
{
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;
    __u32 *buf = (void*)buffer;
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing
    struct iphdr *ip = pkt;
    __u32 *pos = pkt;

    if (ip + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = ip->ihl;

    if ((size * sizeof(*buf)) < sizeof(*ip))
        return NONFATAL_ERR;

    if ( ( pkt + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / sizeof(*buf); i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i >= size)
        {
            break;
        }
        buf[i] = pos[i];
    }

    // Update meta while still valid
    __u8 tos = buffer->ip_hdr.tos;
    ip_update_tos(&(buffer->ip_hdr), meta->ip_tos);
    meta->ip_tos = tos;

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, size * sizeof(*buf)))
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_push_ip(struct xdp_md *ctx, struct raw_ip *buffer)
{
    __u32 *buf = (void*)buffer;
    __u32 size = buffer->ip_hdr.ihl;
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -(size * sizeof(*buf))))
        return FATAL_ERR;

    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    // Update from meta
    ip_update_length(&(buffer->ip_hdr), meta->size_delta);
    __u8 tos = buffer->ip_hdr.tos;
    ip_update_tos(&(buffer->ip_hdr), meta->ip_tos);
    meta->ip_tos = tos;

    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    __u32 *pos = pkt;

    // Safety Check
    if ( ( pos + size ) > end)
        return FATAL_ERR;

    // Copy from buffer to packet
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / sizeof(*buf); i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i >= size)
        {
            break;
        }
        pos[i] = buf[i];
    }

    return NO_ERR;
}

static void ip_update_check(struct iphdr *ip, __u16 delta);

static void ip_update_length(struct iphdr *ip, __u16 delta)
{
    ip->tot_len = htons(ntohs(ip->tot_len) + delta);
    ip_update_check(ip, delta);
}


static void ip_update_tos(struct iphdr *ip, __u8 new_tos)
{
    __u32 old = ntohs(((__u16*)ip)[0]);
    ip->tos = new_tos;
    __u32 delta = ntohs(((__u16*)ip)[0]) - old;
    delta = (delta & 0xFFFF) + (delta >> 16);
    delta = (delta & 0xFFFF) + (delta >> 16);
    ip_update_check(ip, delta);
}


static void ip_update_check(struct iphdr *ip, __u16 delta)
{
    __wsum sum;
    sum = ip->check;
    // RFC 1624 Equation 4
    //Total sum is off by 1
    //sum -= ~old_val;
    //sum -= new_val;

    //This works
    //sum +=htons(-delta);

    // Why does this work???
    
    sum = htons(ntohs(sum) - delta);


    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = sum;
}