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

    __u64 long_result;
    union meta_info info;

    switch(result) {
    case NO_ERR:
        long_result = meta_peek(ctx);

        info.combined_data = long_result;

        if (long_result >> 32 == 0) //If meta valid, adjust header
        {
            tcp_update_check(&(tcp.tcp_hdr),  info.data.csum_delta);
            tcp_update_length(&(tcp.tcp_hdr), info.data.size_delta);
        }
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
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    struct tcphdr *tcp = pkt;

    if (tcp + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = tcp->doff;
    size <<= 2;

    if (size < sizeof(*tcp))
        return NONFATAL_ERR;

    if ( ( pkt + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    __u32 *buf = (void*)buffer, *pos = pkt;
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i == size) 
        {
            break;
        }
        buf[i] = pos[i];
    }

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, size))
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_push_tcp(struct xdp_md *ctx, struct raw_tcp *buffer)
{
    __u32 size = buffer->tcp_hdr.doff;
    size <<= 2;
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -size))
        return FATAL_ERR;

    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Safety Check
    if ( ( pkt + size ) > end)
        return FATAL_ERR;

    // Copy from buffer to packet
    __u32 *buf = (void*)buffer, *pos = pkt;
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i == size) 
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
    tcp->check = sum;
}