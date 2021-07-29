#include "process.h"
#include "meta.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int dropped;

/*
 * Test point for INT removal
 */
SEC("xdp")
int test_int(struct xdp_md *ctx)
{
    __u32 result;
    struct meta_info *meta_info = meta_create(ctx);
    if (!meta_info) {
        dropped++;
        return XDP_DROP;
    }
    meta_info->csum_delta = 0;
    meta_info->ip_tos = 0x17 << 2;
    // meta_info->offset = 14;
    meta_info->size_delta = 0;
    bpf_xdp_adjust_tail(ctx, 14); // Work around, allowing for shrinking the packet until its empty
    result = process_int(ctx);
    bpf_xdp_adjust_tail(ctx, -14); // Work around, allowing for shrinking the packet until its empty
    meta_delete(ctx);
    return result;
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
