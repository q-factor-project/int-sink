#include <linux/udp.h>
#include "udp.h"
#include "cursor.h"
#include "endian.h"

int parse_udphdr(struct hdr_cursor *nh, struct udphdr **udphdr)
{
    struct udphdr *udp = nh->pos;

    if (udp + 1 > nh->end)
        return -1;

    unsigned long hdrsize = sizeof(struct udphdr);

    if (nh->pos + hdrsize > nh->end)
        return -1;

    nh->pos += hdrsize;
    *udphdr = udp;

    return 0;
}

void update_udphdr_check(struct udphdr *udphdr, __u16 delta)
{
    if(udphdr->check)
    {
        __wsum sum;
        sum = udphdr->check;
        sum = htons(ntohs(sum) - delta);
        sum = (sum & 0xFFFF) + (sum >> 16);
        udphdr->check = (sum & 0xFFFF) + (sum >> 16);
    }
}

void udpate_udphdr_length(struct udphdr *udphdr, __u16 delta)
{
    udphdr->len = htons(ntohs(udphdr->len) + delta);
    update_udphdr_check(udphdr, delta); // Update for change in udp header
    update_udphdr_check(udphdr, delta); // Update for change in ip pseudo header
}