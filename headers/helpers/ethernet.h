#if !defined(__ETH_HELPERS_H)
#define __ETH_HELPERS_H
#include "helpers/common.h"
#include <linux/if_ether.h>

static __always_inline __be16 parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    
    if(eth + 1 > data_end)
        return -1;
    
    size_t hdrsize = sizeof(struct ethhdr);

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto;
}
#endif