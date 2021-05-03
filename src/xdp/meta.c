#include "meta.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


__u64 meta_push(struct xdp_md *ctx, __u32 data)
{
    __u32 *meta;
    if (bpf_xdp_adjust_meta(ctx, -sizeof(data)))
        return -1;
    meta = ctx->data_meta;
    if (meta + sizeof(data) > ctx->data)
        return -1;
    *meta = data;
    return 0;
}

__u64 meta_pop(struct xdp_md *ctx)
{
    __u32 *meta;
    __u32 data;
    meta = ctx->data_meta;
    if (meta + sizeof(data) > ctx->data)
        return -1;
    data = *meta;
    if (bpf_xdp_adjust_meta(ctx, -sizeof(data)))
        return -1;
    return data;
}

__u64 meta_peek(struct xdp_md *ctx)
{
    __u32 *meta;
    __u32 data;
    meta = ctx->data_meta;
    if (meta + sizeof(data) > ctx->data)
        return -1;
    data = *meta;
    return data;
}