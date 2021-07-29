#ifndef TYPES_INT_H
#include <asm/byteorder.h>

#define DSCP_INT (0x17)

struct int10_shim_t
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

struct int10_meta_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8   ver:4,
           rep:2
           c: 1;
           e: 1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  e:1,
          c:1,
          rep:2,
          ver:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  m: 1,
          rsvd1:7;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  rsvd1:7,
          m:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  rsvd2:3,
          hopml:5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  hopml:5,
          rsvd2:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8  remainingHopCnt;
    __u16 ins;
    __u16 rsvd3;
};

struct telemetry_report_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  ver:4,
          len:4;
    __u16 nProto:3,
          repMdBits:6,
          reserved:6,
          d:1;
    __u8  q:1,
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

#endif