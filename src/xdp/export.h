#ifndef __EXPORT_H__
#define __EXPORT_H__
#include <linux/bpf.h>

struct  sTcp_Socket{
    __u32 ip_saddr;
    __u16 tcp_sport;
    __u16 resv1;
};

int export_int_metadata(struct xdp_md *ctx, __u16 vlan_id, __u16 metadata_length, __u64 packet_size, __u64 vSrc_Socket);

#endif
