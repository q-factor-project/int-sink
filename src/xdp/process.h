#ifndef __XDP_PROCESS_H__
#define __XDP_PROCESS_H__

#include <linux/types.h>

struct xdp_md;

__u32 driver(struct xdp_md *ctx);

__u32 process_ether(struct xdp_md *ctx);

__u32 process_vlan(struct xdp_md *ctx);

__u32 process_ipv4(struct xdp_md *ctx);

__u32 process_tcp(struct xdp_md *ctx);

__u32 process_udp(struct xdp_md *ctx);

__u32 process_int(struct xdp_md *ctx);

enum PROCESS_ERROR_NUM {
    NO_ERR = 0,
    NONFATAL_ERR = -1,
    FATAL_ERR = -2,
};



#endif