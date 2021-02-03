#if !defined(__ETH_HELPERS_H)
#define __ETH_HELPERS_H
#include "common_helpers.h"
#include <linux/if_ether.h>

static __always_inline __be16 parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    size_t hdrsize = sizeof(*eth);
    __be16 h_proto;

    if(nh->pos + hdrsize > data_end)
        return -1;
    
    nh->pos += hdrsize;
    *ethhdr = eth;
    h_proto = eth->h_proto;

    return h_proto;
}
#endif