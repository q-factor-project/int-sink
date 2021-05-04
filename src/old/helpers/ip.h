#ifndef __HELPER_IP_H__
#define __HELPER_IP_H__

struct hdr_cursor;
struct iphdr;

int parse_iphdr(struct hdr_cursor *nh, struct iphdr **iphdr);

void update_iphdr_check(struct iphdr *iphdr, __u16 delta);

void update_iphdr_length(struct iphdr *iphdr, __u16 delta);

void udpate_iphdr_tos(struct iphdr *iphdr, __u8 new_tos);

#endif