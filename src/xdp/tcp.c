#include "process.h"

#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/memory.h"
#include "helpers/endian.h"

#include "meta.h"

#define DSCP_INT 0x17

struct raw_tcp { // Buffer for ip data
    struct tcphdr tcp_hdr;
    __u8 options[40];
};

static __u32 packet_pop_tcp(struct xdp_md *ctx, struct raw_tcp *buffer);
static __u32 packet_push_tcp(struct xdp_md *ctx, struct raw_tcp *buffer);
static void tcp_update_length(struct tcphdr *tcp, __u16 delta);
static void tcp_update_check(struct tcphdr *tcp, __u16 delta);

__u32 process_tcp(struct xdp_md *ctx)
{
    struct raw_tcp tcp;
    memset(&tcp, 0, sizeof(tcp));
    __u32 result = packet_pop_tcp(ctx, &tcp);

    if (result)
        return result;

    result = process_int(ctx);

    switch(result) {
    case NO_ERR:
        return packet_push_tcp(ctx, &tcp);
        break;
    case NONFATAL_ERR:
        result = packet_push_tcp(ctx, &tcp);
        if (result)
            return result;
        return NONFATAL_ERR;
        break;
    default:
        return result;
    }
}

static __u32 packet_pop_tcp(struct xdp_md *ctx, struct raw_tcp *buffer)
{
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;
    __u32 *buf = (void*)buffer;
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing
    __u32 *pos = pkt;
    struct tcphdr *tcp = pkt;

    if (tcp + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = tcp->doff;

    if ((size * sizeof(*buf)) < sizeof(*tcp))
        return NONFATAL_ERR;

    if ( ( pos + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i >= size)
        {
            break;
        }
        buf[i] = pos[i];
    }

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, size * sizeof(*buf)))
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_push_tcp(struct xdp_md *ctx, struct raw_tcp *buffer)
{
    __u32 *buf = (void*)buffer;
    __u32 size = buffer->tcp_hdr.doff;
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -(size * sizeof(*buf))))
        return FATAL_ERR;

    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    // Update from meta
    tcp_update_check(&(buffer->tcp_hdr),  meta->csum_delta);
    tcp_update_length(&(buffer->tcp_hdr), meta->size_delta);

    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    __u32 *pos = pkt;

    // Safety Check
    if ( ( pos + size ) > end)
        return FATAL_ERR;

    // Copy from buffer to packet
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i >= size)
        {
            break;
        }
        pos[i] = buf[i];
    }

    return NO_ERR;
}

static void tcp_update_length(struct tcphdr *tcp, __u16 delta)
{
    tcp_update_check(tcp, delta);// Update for change in ip pseudo header
}

static void tcp_update_check(struct tcphdr *tcp, __u16 delta)
{
    __wsum sum;
    sum = tcp->check;
    sum = htons(ntohs(sum) - delta);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    tcp->check = sum;
}