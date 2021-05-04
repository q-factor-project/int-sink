#ifndef __TCP_HELPERS_H__
#define __TCP_HELPERS_H__

struct hdr_cursor;
struct tcphdr;

#define MAX_TCP_LENGTH 60

int parse_tcphdr(struct hdr_cursor *nh, struct tcphdr **tcphdr);

void update_tcphdr_check(struct tcphdr *tcphdr, __u16 delta);

void udpate_tcphdr_length(struct tcphdr *tcphdr, __u16 delta);

#endif