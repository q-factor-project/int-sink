#ifndef __HELPERS_ETH_H__
#define __HELPERS_ETH_H__

struct hdr_cursor;
struct ethhdr;

__u32 parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr);

#endif