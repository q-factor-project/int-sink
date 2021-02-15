#if !defined(__UDP_HELPERS_H)
#define __UDP_HELPERS_H
#include "helpers/common.h"
#include <linux/udp.h>

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct udphdr **udphdr)
{
    struct udphdr *udp = nh->pos;

    if (udp + 1 > data_end)
        return -1;

    size_t hdrsize = sizeof(*udp);

    nh->pos += hdrsize;
    *udphdr = udp;

    return 0;
}

static __always_inline void update_udphdr_check(struct udphdr *udphdr,
                                                 __u16 delta)
{
    if(udphdr->check)
    {
        __wsum sum;
        sum = udphdr->check;
        sum = htons(ntohs(sum) - delta);
        sum = (sum & 0xFFFF) + (sum >> 16);
        udphdr->check = (sum & 0xFFFF) + (sum >> 16);
    }
}

// Working
static __always_inline void udpate_udphdr_length(struct udphdr *udphdr, __u16 delta)
{
    udphdr->len = htons(ntohs(udphdr->len) + delta);
    update_udphdr_check(udphdr, delta); // Update for change in udp header
    update_udphdr_check(udphdr, delta); // Update for change in ip pseudo header
}

#endif