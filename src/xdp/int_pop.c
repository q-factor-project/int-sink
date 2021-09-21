#include "process.h"

#include "types/int.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/endian.h"

#include "meta.h"

struct raw_int {
    struct int10_shim_t shim;
    struct int10_meta_t meta_header;
    __u32 data[252];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} int_ring_buffer SEC(".maps");

int int_counter = 0;

static __u32 packet_pop_int(struct xdp_md *ctx);

__u32 process_int(struct xdp_md *ctx)
{
    __u32 result;

    result = packet_pop_int(ctx);

    if (result)
        return result;

    int_counter++;

    return NO_ERR;
}

static __u32 packet_pop_int(struct xdp_md *ctx)
{
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    // Check DSCP/TOS from IP header

    int ip_dscp = meta->ip_tos >> 2;
    if ((ip_dscp & DSCP_INT) ^ DSCP_INT)
        return NONFATAL_ERR;
    
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    struct int10_shim_t *shim = pkt;

    if (shim + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = shim->len << 2;

    if ( ( pkt + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    
    __u64 flags = ((__u64)size << 32) | BPF_F_CURRENT_CPU;

    bpf_perf_event_output(ctx, &int_ring_buffer, flags, &size, 4);

    // Update IP tos, size delta and csum delta
    meta->ip_tos = (shim->DSCP << 2) | (meta->ip_tos & 0b11);

    meta->size_delta -= ((__u16)shim->len) << 2;

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, size))
        return FATAL_ERR;

    return NO_ERR;
}
