#if !defined(__INT_HELPERS_H)
#define __INT_HELPERS_H
#include "common_helpers.h"

#define DSCP_INT (0x17)

struct int14_shim_t
{
    __u8 int_type;
    __u8 rsvd1;
    __u8 len;
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8 DSCP:6,
         rsvd2:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 rsvd2:2,
         DSCP:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct telemetry_report_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        len:4;
    u16 nProto:3,
        repMdBits:6,
        reserved:6,
        d:1;
    u8  q:1,
        f:1,
        hw_id:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  len:4,
        ver:4;
    __u16 d:1,
        reserved:6,
        repMdBits:6,
        nProto:3;
    __u8  hw_id:6,
        f:1,
        q:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u32 sw_id;
    __u32 seqNumber;
    __u32 ingressTimestamp;
} __attribute__((packed));


static __always_inline int parse_int(struct hdr_cursor *nh,
                                              void *data_end,
                                              struct int14_shim_t **int14_shim_t)
{
    struct int14_shim_t *shim = nh->pos;
    size_t hdrsize = ((size_t)shim->len) << 2;

    if (nh->pos + hdrsize > data_end)
        return -1;
    
    nh->pos += hdrsize;
    *int14_shim_t = shim;

    return 0;
}

//Max INT length in 4 byte words
#define MAX_INT_LENGTH 0xF

// calculate the checksum difference for removing INT data
// Producing incorrect checksum
static __always_inline __sum16 int_checksum(struct int14_shim_t *int14_shim_t)
{
    __be32 *ptr = (void*)int14_shim_t;
    __be32 *end = ptr + int14_shim_t->len;
    __u64 sum = 0;
    int i;
    #pragma unroll
    for(i = 0; i < MAX_INT_LENGTH; i ++)
    {
        sum += *ptr;
        ptr++;
        if (ptr >= end)
        {
            break;
        }
    }
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ntohs(sum);
}



#endif