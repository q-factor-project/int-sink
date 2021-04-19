#include <linux/tcp.h>
#include "tcp.h"
#include "cursor.h"
#include "endian.h"

int parse_tcphdr(struct hdr_cursor *nh, struct tcphdr **tcphdr)
{
    struct tcphdr *tcp = nh->pos;

    if(tcp + 1 > nh->end) // Required explicit check
        return -1;

    unsigned long hdrsize = ((unsigned long)tcp->doff) << 2;

    if (hdrsize < sizeof(*tcp))
        return -1;

    if (nh->pos + hdrsize > nh->end)
        return -1;

    nh->pos += hdrsize;
    *tcphdr = tcp;

    return 0;
}

void update_tcphdr_check(struct tcphdr *tcphdr, __u16 delta)
{
    __wsum sum;
    sum = tcphdr->check;
    sum += htons(-delta);
    sum = (sum & 0xFFFF) + (sum >> 16);
    tcphdr->check = (sum & 0xFFFF) + (sum >> 16);
}

void udpate_tcphdr_length(struct tcphdr *tcphdr, __u16 delta)
{
    update_tcphdr_check(tcphdr, delta); // Update checksum for change in IP pseudo header
}