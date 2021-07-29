#include "process.h"

#include <linux/bpf.h>

#define weak __attribute__((weak))

__u32 weak driver(struct xdp_md *ctx)
{
    return XDP_PASS;
}

__u32 weak process_ether(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}

__u32 weak process_vlan(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}

__u32 weak process_ipv4(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}

__u32 weak process_tcp(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}

__u32 weak process_udp(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}

__u32 weak process_int(struct xdp_md *ctx)
{
    return NONFATAL_ERR;
}