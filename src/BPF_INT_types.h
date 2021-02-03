/**
 * In-Band Network Telemetry(INT) types, based on INT v1.0 doc.
 * The following header file does not account for endian-ness.
 */

/*
struct int14_shim_t {
    u8 int_type;
    u8 rsvd1;
    u8 len;
    u8 dscp:6, rsvd2:2;
} __attribute__((packed));

struct int_header_t {
    u8 ver:4, rep:2, c:1, e:1;
    u8 m:1, rsvd1:7;
    u8 rsvd2:3, hop_metadata_len:5;
    u8 remaining_hop_cnt;
    u8 instruction_mask_0003:4, instruction_mask_0407:4;
    u8 instruction_mask_0811:4, instruction_mask_1215:4;
    u16 rsvd3;
} __attribute__((packed));

struct int_switch_id_t {
    u32 switch_id;
} __attribute__((packed));

struct int_level1_port_ids_t {
    u16 ingress_port_id;
    u16 egress_port_id;
} __attribute__((packed));

struct int_hop_latency_t {
    u32 hop_latency;
} __attribute__((packed));

struct int_q_occupancy_t {
    u32 q_id:8, q_occupancy:24;
} __attribute__((packed));

struct int_ingress_tstamp_t {
    u32 ingress_tstamp;
} __attribute__((packed));

struct int_egress_tstamp_t {
    u32 egress_tstamp;
} __attribute__((packed));

struct int_level2_port_ids_t {
    u32 ingress_port_id;
    u32 egress_port_id;
} __attribute__((packed));

struct int_egress_port_tx_util_t {
    u32 egress_port_tx_util;
} __attribute__((packed));

struct ethernet_t {
    u64 dstAddr:48;
    u64 srcAddr:48;
    u16 etherType;
} __attribute__((packed));

struct ipv4_t {
    u8 version:4, ihl:4;
    u8 dscp:6, ecn:2;

    u16 totalLen;
    u16 identification;
    u16 flags:3, fragOffset:13;
    u8 ttl;
    u8 protocol;
    u16 hdrChecksum;
    u32 srcAddr;
    u32 dstAddr;
} __attribute__((packed));

struct tcp_t {
    u16 srcPort;
    u16 dstPort;
    u32 seqNo;
    u32 ackNo;
    u8 dataOffset:4, res:4;
    u8 flags;
    u16 window;
    u16 checksum;
    u16 urgetnPtr;
} __attribute__((packed));

struct udp_t {
    u16 srcPort;
    u16 dstPort;
    u16 length_;
    u16 checksum;
} __attribute__((packed));
*/

// Protocols

/* Ethernet frame */
struct eth_tp {
    u64 dst:48;
    u64 src:48;
    u16 type;
} __attribute__((packed));

/* VLAN Ethertype */
struct vlan_tp {
    u16 vid; // TODO: FIX04 change to u16 vid:12
    u16 type;
} __attribute__((packed));

/* INT Telemetry report */
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
    u8  len:4,
        ver:4;
    u16 d:1,
        reserved:6,
        repMdBits:6,
        nProto:3;
    u8  hw_id:6,
        f:1,
        q:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    u32 sw_id;
    u32 seqNumber;
    u32 ingressTimestamp;
} __attribute__((packed));

/* INT shim */
struct INT_shim_v10_t {
    u8 type;
    u8 shimRsvd1;
    u8 length;
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  DSCP:6,
        r:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  r:2,
        DSCP:6;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* INT metadata header */
struct INT_md_fix_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        rep:2,
        c:1,
        e:1;
    u8  m:1,
        rsvd_1:7;
    u8  rsvd_2:3,
        hopMlen:5,
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  e:1,
        c:1,
        rep:2,
        ver:4;
    u8  rsvd_1:7,
        m:1;
    u8  hopMlen:5,
        rsvd_2:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    u8  remainHopCnt;
    u16 ins;
    u16 rsvd2;
} __attribute__((packed));