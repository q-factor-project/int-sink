#if !defined(__INT_HELPERS_H)
#define __INT_HELPERS_H
#include "helpers/common.h"
#include "types/int.h"

static __always_inline int parse_int(struct hdr_cursor *nh,
                                              void *data_end,
                                              struct int14_shim_t **int14_shim_t)
{
    struct int14_shim_t *shim = nh->pos;
    
    if (shim + 1 > data_end)
        return -1;
    
    size_t hdrsize = ((size_t)shim->len) << 2;

    nh->pos += hdrsize;
    *int14_shim_t = shim;

    return 0;
}

//Max INT length in 4 byte words
#define MAX_INT_LENGTH 0xFF

// calculate the checksum difference for removing INT data
// Producing incorrect checksum
static __always_inline __u16 int_checksum(struct int14_shim_t *int14_shim_t)
{
    __be32 *ptr = (void*)int14_shim_t;
    __be32 *end = ptr + int14_shim_t->len;
    __u64 sum = 0;

    #pragma unroll
    for (int i = 0; i < MAX_INT_LENGTH; i++)
    {
        if (ptr < end)
        {
            sum += *ptr;
            ptr++;
        }
    }

    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ntohs(sum);
}



#endif