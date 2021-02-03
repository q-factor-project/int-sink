#if !defined(__IP_HELPERS_H)
#define __IP_HELPERS_H
#include "common_helpers.h"
#include <linux/ip.h>

#define MAX_IP_LENGTH (sizeof(struct iphdr) + MAX_IPOPTLEN)

static __always_inline __u8 parse_iphdr(struct hdr_cursor *nh,
                                      void* data_end,
                                      struct iphdr **iphdr)
{
    struct iphdr *ip = nh->pos;
    size_t hdrsize = ((size_t)ip->ihl) << 2; // Read size of header in bytes
    __u8 protocol;

    if(nh->pos + hdrsize > data_end)
        return -1;

    // Not checking checksum, not duty of this module
    //if(calc_iphdr_checksum(ip, hdrsize) != 0)
    //    return -1;

    nh->pos += hdrsize;
    *iphdr = ip;
    protocol = ip->protocol;

    return protocol;
}

static __always_inline void update_iphdr_length(struct iphdr *iphdr,
                                                __u16 delta)
{
    __wsum sum;
    __be16 old;
    iphdr->tot_len = htons(ntohs(iphdr->tot_len) + delta);
    sum = iphdr->check;
    sum += htons(-delta);
    sum = (sum & 0xFFFF) + (sum >> 16);
    iphdr->check = (sum & 0xFFFF) + (sum >> 16);
}

#endif