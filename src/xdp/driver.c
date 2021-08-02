#include "process.h"
#include "meta.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int int_counter = 0;
int counter = 0;
int dropped = 0;

static struct meta_info * meta_create(struct xdp_md *ctx);
static __u32 meta_delete(struct xdp_md *ctx);

/*
 * Entry point into xdp program.
 */
SEC("xdp")
__u32 driver_entry(struct xdp_md *ctx)
{
    return driver(ctx);
}



__u32 driver(struct xdp_md *ctx)
{
    counter++;
    __u32 result;
    struct meta_info *meta_info = meta_create(ctx);
    if (!meta_info) {
        dropped++;
        return XDP_DROP;
    }
    meta_info->csum_delta = 0;
    meta_info->ip_tos = 0;
    meta_info->offset = 0;
    meta_info->size_delta = 0;
    bpf_xdp_adjust_tail(ctx, 14); // Work around, allowing for shrinking the packet until its empty
    result = process_ether(ctx);
    bpf_xdp_adjust_tail(ctx, -14); // Work around, allowing for shrinking the packet until its empty
    meta_delete(ctx);
    switch(result) {
    case NO_ERR:// INT PACKET
        int_counter++;
        return XDP_PASS;
    case NONFATAL_ERR:// NON-INT PACKET
        return XDP_PASS;
    case FATAL_ERR://FATAL ERROR, SHOULD DROP
    default:
        dropped++;
        return XDP_DROP;
    }
}

static struct meta_info * meta_create(struct xdp_md *ctx)
{
    if (bpf_xdp_adjust_meta(ctx, (int)(-sizeof(struct meta_info))))
        return 0;
    return meta_get(ctx);
}

static __u32 meta_delete(struct xdp_md *ctx)
{
    if (bpf_xdp_adjust_meta(ctx, sizeof(struct meta_info)))
        return -1;
    return 0;
}