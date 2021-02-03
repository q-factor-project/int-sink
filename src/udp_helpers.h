#if !defined(__UDP_HELPERS_H)
#define __UDP_HELPERS_H
#include "common_helpers.h"
#include <linux/udp.h>

/*
static __always_inline __sum16 calc_udphdr_checksum(__sum16 sum, void *hdr)
{
    __wsum wide_checksum = sum;
    const __u16 *ptr = hdr;

    #pragma unroll
    for(size_t i = 0; i < sizeof(struct udphdr) / 2; i += 1)
    {
        wide_checksum += ptr[i];
    }

    // Need a better folding strategy, as this does not work if we gett another carry

    wide_checksum = (wide_checksum & 0xFFFF) + (wide_checksum >> 16);

    __sum16 checksum = wide_checksum;

    return ~checksum;
}
*/

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct udphdr **udphdr)
{
    struct udphdr *udp = nh->pos;
    size_t hdrsize = sizeof(*udp);

    if (nh->pos + hdrsize > data_end)
        return -1;

    // Forget about checking the checksum, thats not the purpose of this module
    /*if(udp->check != 0)//Ignore checksum if == to 0
        if (calc_udphdr_checksum(udp) != 0) // validate that the sum is 0
            return -1;
    */
    nh->pos += hdrsize;
    *udphdr = udp;

    return 0;
}

static __always_inline void update_udphdr_check(struct udphdr *udphdr,
                                                 __u16 delta)
{
    printf("Delta %4x\n", delta);
    if(udphdr->check)
    {
        __wsum sum;
        sum = udphdr->check;
        sum += htons(-delta);
        sum = (sum & 0xFFFF) + (sum >> 16);
        udphdr->check = (sum & 0xFFFF) + (sum >> 16);
    }
}




/*
static __always_inline int recalc_udphdr(struct udphdr *udphdr,
                                         void *data_end)
{
    size_t hdrsize = sizeof(*udphdr);
    if((void*)udphdr + hdrsize > data_end)
        return -1;

    size_t length = data_end - (void*)udphdr;

    udphdr->len = length;
    udphdr->check = 0;
    udphdr->check = calc_udphdr_checksum(udphdr);


}
*/

#endif