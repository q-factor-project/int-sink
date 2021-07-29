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

static __u32 packet_pop_int(struct xdp_md *ctx, struct raw_int *buffer);
static __u16 int_checksum(struct raw_int *buffer);

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct raw_int);
    __uint(max_entries, 1);
} int_buffer SEC(".maps"); // Can not replace with output buffer

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14);
} int_ring_buffer SEC(".maps");

__u32 process_int(struct xdp_md *ctx)
{
    struct raw_int *int_data;
    __u32 result;

    __u32 key = 0;

    // Prepare buffer

    int_data = bpf_map_lookup_elem(&int_buffer, &key);

    if(!int_data)
        return FATAL_ERR;

    result = packet_pop_int(ctx, int_data);

    if (result)
        return result;

    int size = int_data->shim.len << 2;

    bpf_ringbuf_output(&int_ring_buffer, int_data, size, 0);

    return NO_ERR;
}

static __u32 packet_pop_int(struct xdp_md *ctx, struct raw_int *buffer)
{
    struct meta_info *meta = meta_get(ctx);
    if (!meta)
        return FATAL_ERR;

    // Check DSCP/TOS from IP header

    int ip_dscp = meta->ip_tos >> 2;
    if ((ip_dscp & DSCP_INT) ^ DSCP_INT)
        return NONFATAL_ERR;

    __u32 *buf = (void*)buffer;
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    struct int10_shim_t *shim = pkt;
    __u32 *pos = pkt;

    if (shim + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = shim->len;

    if ((size * sizeof(*buf)) < sizeof(struct int10_shim_t))
        return NONFATAL_ERR;

    if ( ( pos + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to buffer
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / sizeof(*buf); i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1) || i >= size )
        {
            break;
        }
        buf[i] = pos[i];
    }

    // Update IP tos, size delta and csum delta
    meta->ip_tos = (buffer->shim.DSCP << 2) | (meta->ip_tos & 0b11);

    __u32 csum_delta = meta->csum_delta;
    csum_delta += (__u16)(~int_checksum(buffer));
    csum_delta = (csum_delta & 0xFFFF) + (csum_delta >> 16);
    meta->csum_delta = (csum_delta & 0xFFFF) + (csum_delta >> 16); // Only single fold required

    meta->size_delta -= ((__u16)buffer->shim.len) << 2;

    // Shrinking packet
    if (bpf_xdp_adjust_head(ctx, size * sizeof(*buf)))
        return FATAL_ERR;

    return NO_ERR;
}

static __u16 int_checksum(struct raw_int *buffer)
{
    __u32 size = buffer->shim.len;

    __u64 sum = 0;

    __u32 *buf = (void*)buffer;

    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / sizeof(*buf); i++)
    {   
        if ((buf + i + 1) > (buffer + 1) || i >= size)
        {
            break;
        }
        sum += buf[i];
    }

    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ntohs(sum);
}