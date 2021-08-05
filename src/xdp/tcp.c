#include "process.h"

#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/memory.h"
#include "helpers/endian.h"

static __u32 packet_pop_tcp(struct xdp_md *ctx, struct tcphdr *buffer);
static __u32 packet_push_tcp(struct xdp_md *ctx, struct tcphdr *buffer);

__u32 process_tcp(struct xdp_md *ctx)
{
    struct tcphdr tcp;
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

static __u32 packet_pop_tcp(struct xdp_md *ctx, struct tcphdr *tcp)
{
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    if (pkt + sizeof(*tcp) > end)
        return NONFATAL_ERR;

    // End parsing
    
    // Copy from packet to buffer
    memcpy(tcp, pkt, sizeof(*tcp));

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, sizeof(*tcp)))
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_push_tcp(struct xdp_md *ctx, struct tcphdr *tcp)
{
    // Expand packet
    if (bpf_xdp_adjust_head(ctx, -(int)(sizeof(*tcp))))
        return FATAL_ERR;

    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Safety check
    if ( ( pkt + sizeof(*tcp) ) > end)
        return FATAL_ERR;
    
    // Copy from buffer to packet
    memcpy(pkt, tcp, sizeof(*tcp));

    return NO_ERR;
}
