#ifndef __EXPORT_H__
#define __EXPORT_H__
#include <linux/bpf.h>

struct  sTcp_Socket{
    __u32 ip_saddr;
    __u16 tcp_sport;
    __u16 resv1;
};

int export_int_metadata(struct xdp_md *ctx, __u16 vlan_id, __u64 metadata_length_and_pInfo, __u64 packet_size, __u64 vSocket_Ipinfo);

#endif
