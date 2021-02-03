#if !defined(__TCP_HELPERS_H)
#define __TCP_HELPERS_H
#include "common_helpers.h"
#include <linux/tcp.h>

#define MAX_TCP_LENGTH 60

/*
static __always_inline __sum16 calc_tcphdr_checksum(void* hdr,
                                                    size_t length)
{
    __wsum wide_checksum = 0;
    const __u16 *ptr = hdr;

    #pragma unroll
    for(size_t i = 0; i < MAX_TCP_LENGTH / 2; i += 1)
    {
        if (i >= length / 2)
            break;
        wide_checksum += ptr[i];
    }

    __sum16 checksum = (wide_checksum & 0xFFFF) + (wide_checksum >> 16);

    return ~checksum;
}
*/

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct tcphdr **tcphdr)
{
    struct tcphdr *tcp = nh->pos;
    size_t hdrsize = ((size_t)tcp->doff) << 2;

    if(nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *tcphdr = tcp;

    return 0;
}

static __always_inline void update_tcphdr_check(struct tcphdr *tcphdr,
                                                 __u16 delta)
{
    __wsum sum;
    sum = tcphdr->check;
    sum += htons(-delta);
    sum = (sum & 0xFFFF) + (sum >> 16);
    tcphdr->check = (sum & 0xFFFF) + (sum >> 16);
}



#endif