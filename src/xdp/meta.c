#include "meta.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


__u64 meta_push(struct xdp_md *ctx, __u32 input)
{
    __u32 *meta;
    void *data;
    if (bpf_xdp_adjust_meta(ctx, (int)(-sizeof(input))))
        return -1;
    meta = (void*)(long)ctx->data_meta;
    data = (void*)(long)ctx->data;
    if (meta + 1 > data)
        return -1;
    *meta = input;
    return 0;
}

__u64 meta_pop(struct xdp_md *ctx)
{
    __u32 *meta;
    void *data;
    __u32 output;
    meta = (void*)(long)ctx->data_meta;
    data = (void*)(long)ctx->data;
    if (meta + 1 > data)
        return -1;
    output = *meta;
    if (bpf_xdp_adjust_meta(ctx, sizeof(output)))
        return -1;
    return output;
}

__u64 meta_peek(struct xdp_md *ctx)
{
    __u32 *meta;
    void *data;
    __u32 output;
    meta = (void*)(long)ctx->data_meta;
    data = (void*)(long)ctx->data;
    if (meta + 1 > data)
        return -1;
    output = *meta;
    return output;
}