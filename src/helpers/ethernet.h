#ifndef __ETH_HELPERS_H__
#define __ETH_HELPERS_H__

struct hdr_cursor;
struct ethhdr;

int parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr);

#endif