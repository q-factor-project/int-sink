#ifndef __HELPER_UDP_H__
#define __UDP_HELPERS_H

struct hdr_cursor;
struct udphdr;

int parse_udphdr(struct hdr_cursor *nh, struct udphdr **udphdr);

void update_udphdr_check(struct udphdr *udphdr, __u16 delta);

void udpate_udphdr_length(struct udphdr *udphdr, __u16 delta);

#endif