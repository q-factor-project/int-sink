#if !defined(__ETH_HELPERS_H)
#define __ETH_HELPERS_H
#include "common.h"
#include <linux/if_ether.h>

static __always_inline __be16 parse_ethhdr(struct hdr_cursor *nh,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    
    if(eth + 1 > nh->end)
        return -1;
    
    size_t hdrsize = sizeof(struct ethhdr);

    if(nh->pos + hdrsize > nh->end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return ntohs(eth->h_proto);
}
#endif