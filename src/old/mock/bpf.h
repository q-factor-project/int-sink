#ifndef MOCK_BPF_H
#define MOCK_BPF_H

#include "types/xdp.h"
#include <linux/types.h>

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

#define SEC(name) 

long bpf_xdp_adjust_head(struct xdp_md *ctx, int length);

__s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed);

#endif