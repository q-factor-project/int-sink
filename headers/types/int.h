#pragma once
#include <asm/byteorder.h>

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
};

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
};