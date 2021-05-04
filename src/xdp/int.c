#include "process.h"

#include "types/int.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "meta.h"
#include "helpers/endian.h"

struct raw_int {
    struct int14_shim_t shim;
    struct telemetry_report_v10_t telemetry_report;
    __u32 data[249];
};

static __u32 packet_pop_int(struct xdp_md *ctx, struct raw_int *buffer);
static __u16 int_checksum(struct raw_int *buffer);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct raw_int);
    __uint(max_entries, 1);
} int_buffer SEC("maps"); // Can replace with just the output buffer


__u32 process_int(struct xdp_md *ctx)
{
    struct raw_int *int_data;
    __u32 result;

    __u32 key = 0;

    // Check DSCP/TOS from IP header

    result = meta_pop(ctx);

    result >>= 2;

    if ((result & DSCP_INT) ^ DSCP_INT)
        return NONFATAL_ERR;

    // Prepare buffer

    int_data = bpf_map_lookup_elem(&int_buffer, &key);

    result = packet_pop_int(ctx, int_data);

    if (result)
        return result;

    // Successfully copied to buffer

    // 3 Values need to be sent back up
    // DSCP - almost completely unimportant

    result = meta_push(ctx, int_data->shim.DSCP << 2);

    if (result)
        return FATAL_ERR;

    // Size delta - VERY IMPORTANT
    // CSUM delta - VERY IMPORTANT

    union meta_info info;

    info.data.csum_delta = ~int_checksum(int_data);
    info.data.size_delta = -(((__u16)int_data->shim.len) << 2);
    
    result = meta_push(ctx, info.combined_data);

    if (result)
        return FATAL_ERR;

    return NO_ERR;
}

static __u32 packet_pop_int(struct xdp_md *ctx, struct raw_int *buffer)
{
    void *pkt = (void*)(long)ctx->data;
    void *end = (void*)(long)ctx->data_end;

    // Parsing

    struct int14_shim_t *shim = pkt;

    if (shim + 1 > end)
        return NONFATAL_ERR;
    
    __u32 size = shim->len;
    size <<= 2;

    if (size < sizeof(struct int14_shim_t) + sizeof(struct telemetry_report_v10_t))
        return NONFATAL_ERR;

    if ( ( pkt + size ) > end)
        return NONFATAL_ERR;

    // End parsing

    // Copy from packet to 
    __u32 *buf = (void*)buffer, *pos = pkt;
    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((pos + i + 1) > end || (buf + i + 1) > (buffer + 1)) 
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

static __u16 int_checksum(struct raw_int *buffer)
{
    __u32 size = buffer->shim.len;
    size <<= 2;

    __u64 sum = 0;

    __u32 *buf = (void*)buffer;

    #pragma unroll
    for(int i = 0; i < sizeof(*buffer) / 4; i++)
    {   
        if ((buf + i + 1) > (buffer + 1)) 
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