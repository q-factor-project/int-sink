#ifndef __XDP_INSERT_H__
#define __XDP_INSERT_H__

#include <linux/types.h>

struct xdp_md *ctx;

__u32 insert_from_buffer(struct xdp_md *ctx, void *buffer, __u32 size);

__u32 extract_to_buffer(struct xdp_md *ctx, void *buffer, __u32 size);

#endif // __XDP_INSERT_H__