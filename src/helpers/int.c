#include "../types/int.h"
#include "int.h"
#include "cursor.h"
#include "endian.h"

//Max INT length in 4 byte words
#define MAX_INT_LENGTH 0xFF

int parse_inthdr(struct hdr_cursor *nh, struct int14_shim_t **int14_shim_t)
{
    struct int14_shim_t *shim = nh->pos;
    
    if (shim + 1 > nh->end)
        return -1;
    
    nh->pos += sizeof(struct int14_shim_t);

    unsigned long hdrsize = ((unsigned long)shim->len) << 2;

    if (hdrsize < sizeof(struct int14_shim_t))
        return -1;

    hdrsize -= sizeof(struct int14_shim_t);

    if (((void *)shim)  + hdrsize > nh->end)//Attach packet bounds to shim
        return -1;

    nh->pos += hdrsize;
    *int14_shim_t = shim;

    return 0;
}

// calculate the checksum difference for removing INT data
__u16 int_checksum(struct int14_shim_t *int14_shim_t, void *data_end)
{
    void *ptr = (void*)int14_shim_t;
    void *end = ptr + (int14_shim_t->len << 2);
    __u64 sum = 0;

    ptr += sizeof(__be32);
    
    #pragma unroll
    for (int i = 0; i < MAX_INT_LENGTH; i++)
    {
        if (ptr > end || ptr > data_end)
        {
            break;
        }
        ptr -= sizeof(__be32);
        sum += *((__be32*)ptr);
        ptr += sizeof(__be32) * 2;
    }

    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ntohs(sum);
}