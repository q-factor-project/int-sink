#ifndef __XDP_META_H__
#define __XDP_META_H__

struct xdp_md;

__u64 meta_push(struct xdp_md *ctx, __u32 data);

__u64 meta_pop(struct xdp_md *ctx);

__u64 meta_peek(struct xdp_md *ctx);

#endif