#include "ethernet.h"
#include <linux/if_ether.h>
#include "cursor.h"
#include "endian.h"

__u32 parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    
    if(eth + 1 > nh->end)
        return -1;
    
    __u32 hdrsize = sizeof(struct ethhdr);

    if(nh->pos + hdrsize > nh->end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return ntohs(eth->h_proto);
}