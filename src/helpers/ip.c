#include <linux/ip.h>
#include "ip.h"
#include "cursor.h"
#include "endian.h"

int parse_iphdr(struct hdr_cursor *nh, struct iphdr **iphdr)
{
    struct iphdr *ip = nh->pos;
    
    if(ip + 1 > nh->end) // Required explicit check before reading anything in packet
        return -1;

    unsigned long hdrsize = ((unsigned long)ip->ihl) << 2; // Read size of header in bytes

    if (hdrsize != sizeof(struct iphdr))
        return -1;

    if (nh->pos + hdrsize > nh->end)
        return -1;

    nh->pos += sizeof(struct iphdr);
    // nh->pos += hdrsize;
    *iphdr = ip;

    return ip->protocol; // Return Protocol
}

void update_iphdr_check(struct iphdr *iphdr, __u16 delta)
{
    __wsum sum;
    sum = iphdr->check;
    // RFC 1624 Equation 4
    //Total sum is off by 1
    //sum -= ~old_val;
    //sum -= new_val;

    //This works
    //sum +=htons(-delta);

    // Why does this work???
    
    sum = htons(ntohs(sum) - delta);


    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    iphdr->check = sum;
}

void update_iphdr_length(struct iphdr *iphdr, __u16 delta)
{
    iphdr->tot_len = htons(ntohs(iphdr->tot_len) + delta);
    update_iphdr_check(iphdr, delta);
}

void udpate_iphdr_tos(struct iphdr *iphdr, __u8 new_tos)
{
    __u16 old = ntohs(((__u16*)iphdr)[0]);
    iphdr->tos = new_tos;
    __u32 delta = ntohs(((__u16*)iphdr)[0]) - old;
    delta = (delta & 0xFFFF) + (delta >> 16);
    delta = (delta & 0xFFFF) + (delta >> 16);
    update_iphdr_check(iphdr, delta);
}