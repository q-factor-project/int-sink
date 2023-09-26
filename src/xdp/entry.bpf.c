#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include "export.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

int ebpf_filter(struct xdp_md *ctx);

SEC("xdp")
int entry(struct xdp_md *ctx) {
    return ebpf_filter(ctx);
}