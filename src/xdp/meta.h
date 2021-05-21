#ifndef __XDP_META_H__
#define __XDP_META_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct xdp_md;

struct meta_info
{
    __be16 csum_delta;
    __u16 size_delta;
    __u32 offset;
    __u8 ip_tos;
};

static struct meta_info * meta_get(struct xdp_md *ctx)
{
    struct meta_info *meta = (void*)(long)ctx->data_meta;
    void *data = (void*)(long)ctx->data;
    if (meta + 1 > data)
        return 0;
    return meta;
}

#endif