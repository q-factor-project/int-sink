#ifndef __INT_DEFS_H__
#define __INT_DEFS_H__

#include <linux/types.h>
#include <asm/byteorder.h>

/* INT Telemetry report */
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
    __be32 sw_id;
    __be32 seqNumber;
    __be32 ingressTimestamp;
} __attribute__((packed));

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
         dscp:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};

struct INT_md_fix_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  ver:4,
        rep:2,
        c:1,
        e:1;
    __u8  m:1,
        rsvd_1:7;
    __u8  rsvd_2:3,
        hopMlen:5,
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  e:1,
        c:1,
        rep:2,
        ver:4;
    __u8  rsvd_1:7,
        m:1;
    __u8  hopMlen:5,
        rsvd_2:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8  remainHopCnt;
    __be16 ins;
    __u16 rsvd2;
} __attribute__((packed));

struct int_hop_metadata {
    __be32 switch_id;
    __be16 ingress_port_id;
    __be16 egress_port_id;
    __be32 hop_latency;
    __be32 queue_info; //Very difficult to convert in and out of big endian due to bit field sizes
    __be32 ingress_time;
    __be32 egress_time;
};

#endif