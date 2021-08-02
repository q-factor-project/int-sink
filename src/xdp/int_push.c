#include "process.h"

#include "types/int.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helpers/endian.h"

#include "helpers/memory.h"

#include "meta.h"

struct raw_int {
    struct int10_shim_t shim;
    struct int10_meta_t meta_header;
    __u8 data[4 * 6];
};

static __u16 int_checksum(struct raw_int *buffer);

__u32 process_int(struct xdp_md *ctx)
{
    struct meta_info *meta;

    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct raw_int)))
        return FATAL_ERR;

    if (ctx->data + sizeof(struct raw_int) > ctx->data_end)
        return FATAL_ERR;

    if (!(meta = meta_get(ctx)))
        return FATAL_ERR;

    struct raw_int data = 
    {
        .shim = {
            .len = sizeof(struct raw_int) / sizeof(__u32),
            .DSCP = meta->ip_tos,
            .int_type = 1,
            .rsvd1 = 0,
            .rsvd2 = 0,
        },
        .meta_header = {
            .ver = 1,
            .ins = htons(0xfc00),
            .hopml = 6,
            .remainingHopCnt = 0xff,
            .c = 0,
            .e = 0,
            .m = 0,
            .rep = 0,
            .rsvd1 = 0,
            .rsvd2 = 0,
            .rsvd3 = 0,
        },
        .data = {
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        },
    };

    ((__be16 *)data.data)[11] = htons((__u16)sizeof(struct raw_int));
    ((__be16 *)data.data)[11] = ~htons(int_checksum(&data));

    memcpy((void*)(long)ctx->data, &data, sizeof(data));

    meta->ip_tos = (DSCP_INT << 2) | (meta->ip_tos & 0b11);

    __u32 csum_delta = meta->csum_delta;
    csum_delta += int_checksum(&data);
    csum_delta = (csum_delta & 0xFFFF) + (csum_delta >> 16);
    meta->csum_delta = (csum_delta & 0xFFFF) + (csum_delta >> 16);

    meta->size_delta += sizeof(struct raw_int);


    return NONFATAL_ERR;
}

static __u16 int_checksum(struct raw_int *buffer)
{
    __u32 size = buffer->shim.len;

    __be64 sum = 0;

    __be32 *buf = (void*)buffer;

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