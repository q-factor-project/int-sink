#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include "helpers.h"
#include "export.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct counter_set);
} counters_map SEC(".maps");

struct ethernet_t {
    struct ethhdr hdr;
    __u8 valid;
};

struct vlan_t {
    struct vlanhdr hdr;
    __u8 valid;
};

struct ipv4_t {
    struct iphdr hdr;
    __u8 valid;
};

struct udp_t {
    struct udphdr hdr;
    __u8 valid;
};

struct tcp_t {
    struct tcphdr hdr;
    __u8 valid;
};

struct int_shim_t {
    struct int10_shim_t hdr;
    __u8 valid;
};

struct headers {
    struct ethernet_t ethernet;
    struct vlan_t vlan;
    struct vlan_t qinq;
    struct ipv4_t ip;
    struct udp_t udp;
    struct tcp_t tcp;
    struct int_shim_t shim;
};

inline __u16 csum16_add(__u16 csum, __u16 addend) {
    __u16 res = csum;
    res += addend;
    return (res + (res < addend));
}
inline __u16 csum16_sub(__u16 csum, __u16 addend) {
    return csum16_add(csum, ~addend);
}
inline __u16 csum_replace2(__u16 csum, __u16 old, __u16 new) {
    return (~csum16_add(csum16_sub(~csum, old), new));
}

SEC("xdp")
int ebpf_filter(struct xdp_md *ctx) {
    void* packetStart = (void*)(long)ctx->data;
    void* packetEnd = (void*)(long)ctx->data_end;
    __u64 packetSize = packetEnd - packetStart;
    unsigned packetOffsetInBytes = 0;
    __u16 metadata_length = 0;
    struct headers hdr = {
        {{}, 0},
        {{}, 0},
        {{}, 0},
        {{}, 0},
        {{}, 0},
        {{}, 0},
        {{}, 0},
    };
    goto start;
// Goto reject, if packet malformed
    reject: { return XDP_DROP; }
// Goto pass, if processing complete
    pass: { return XDP_PASS; }
// Goto accept, if packet needs to be updated on egress
start: {
        __u32 key = 0; // Count all packets received
        struct counter_set *counter_set_ptr = bpf_map_lookup_elem(&counters_map, &key);
        if (counter_set_ptr)
        {
            __sync_fetch_and_add(&(counter_set_ptr->packets), 1);
            __sync_fetch_and_add(&(counter_set_ptr->bytes), packetSize);
        }
        goto parse_ether;
    }
parse_ether: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct ethhdr)) { goto reject; }
        struct ethhdr* eth_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.ethernet.hdr), eth_ptr, sizeof(struct ethhdr));
        hdr.ethernet.valid = 1;
        packetOffsetInBytes += sizeof(struct ethhdr);
        switch (eth_ptr->h_proto) {
            case bpf_htons(ETH_P_8021Q): goto parse_vlan;
            case bpf_htons(ETH_P_IP): goto parse_ipv4;
            default: goto pass;
        }
    }
parse_vlan: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct vlanhdr)) { goto reject; }
        struct vlanhdr* vlan_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.vlan.hdr), vlan_ptr, sizeof(struct vlanhdr));
        hdr.vlan.valid = 1;
        packetOffsetInBytes += sizeof(struct vlanhdr);
        switch (vlan_ptr->h_proto) {
            case bpf_htons(ETH_P_8021Q): goto parse_qinq;
            case bpf_htons(ETH_P_IP): goto parse_ipv4;
            default: goto pass;
        }
    }
parse_qinq: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct vlanhdr)) { goto reject; }
        struct vlanhdr* vlan_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.qinq.hdr), vlan_ptr, sizeof(struct vlanhdr));
        hdr.qinq.valid = 1;
        packetOffsetInBytes += sizeof(struct vlanhdr);
        switch (vlan_ptr->h_proto) {
            case bpf_htons(ETH_P_IP): goto parse_ipv4;
            default: goto pass;
        }
    }
parse_ipv4: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct iphdr)) { goto reject; }
        struct iphdr* ip_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.ip.hdr), ip_ptr, sizeof(struct iphdr));
        hdr.ip.valid = 1;
        packetOffsetInBytes += sizeof(struct iphdr);
        if (ip_ptr->dscp != INT_DSCP) { goto pass; } // Confirm packet is INT
        
        switch (ip_ptr->protocol) {
            case 0x6: goto parse_tcp;
            case 0x11: goto parse_udp;
            default: goto pass;
        }
    }
parse_udp: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct udphdr)) { goto reject; }
        struct udphdr* udp_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.udp.hdr), udp_ptr, sizeof(struct udphdr));
        hdr.udp.valid = 1;
        packetOffsetInBytes += sizeof(struct udphdr);
        goto parse_shim;
    }
parse_tcp: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct tcphdr)) { goto reject; }
        struct tcphdr* tcp_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.tcp.hdr), tcp_ptr, sizeof(struct tcphdr));
        hdr.tcp.valid = 1;
        packetOffsetInBytes += sizeof(struct tcphdr);
        goto parse_shim;
    }
parse_shim: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct int10_shim_t)) { goto reject; }
        struct int10_shim_t* shim_ptr = packetStart + packetOffsetInBytes;
        memcpy(&(hdr.shim.hdr), shim_ptr, sizeof(struct int10_shim_t));  
        hdr.shim.valid = 1;
        packetOffsetInBytes += sizeof(struct int10_shim_t);
        metadata_length = shim_ptr->len * 4;
        metadata_length -= sizeof(struct int10_shim_t);
        goto parse_metadata_header;
    }
parse_metadata_header: {
        if (packetEnd < packetStart +  packetOffsetInBytes + sizeof(struct INT_md_fix_v10_t)) { goto reject; }
        if (metadata_length < sizeof(struct INT_md_fix_v10_t)) { goto reject; }
        //struct INT_md_fix_v10_t* metadata_hdr_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct INT_md_fix_v10_t);
        metadata_length -= sizeof(struct INT_md_fix_v10_t);
        goto export_int_metadata;
    }
export_int_metadata: {
        if (bpf_xdp_adjust_head(ctx, packetOffsetInBytes)) { goto reject; };
        if (export_int_metadata(ctx, bpf_ntohs(hdr.vlan.hdr.h_vlan_tag), metadata_length, packetSize)) { goto reject; };
        packetOffsetInBytes = metadata_length;
        goto accept;
    }
accept: {
        if (hdr.shim.valid)
        {
            __u16 int_len = (__u16)hdr.shim.hdr.len * 4;
            if (hdr.udp.valid)
            {
                hdr.udp.hdr.len = bpf_htons(bpf_ntohs(hdr.udp.hdr.len) - int_len);
                hdr.udp.hdr.check = 0;
            }
            if (hdr.ip.valid)
            {
                hdr.ip.hdr.check = bpf_htons(csum_replace2(
                    bpf_ntohs(hdr.ip.hdr.check),
                    bpf_ntohs(hdr.ip.hdr.tot_len),
                    bpf_ntohs(hdr.ip.hdr.tot_len) - int_len
                ));
                hdr.ip.hdr.tot_len = bpf_htons(bpf_ntohs(hdr.ip.hdr.tot_len) - int_len);
                hdr.ip.hdr.check = bpf_htons(csum_replace2(
                    bpf_ntohs(hdr.ip.hdr.check),
                    ((__u16)hdr.ip.hdr.version << 12) | ((__u16)hdr.ip.hdr.ihl << 8) | ((__u16)hdr.ip.hdr.dscp << 2)   | ((__u16)hdr.ip.hdr.ecn),
                    ((__u16)hdr.ip.hdr.version << 12) | ((__u16)hdr.ip.hdr.ihl << 8) | ((__u16)hdr.shim.hdr.dscp << 2) | ((__u16)hdr.ip.hdr.ecn)
                ));
                hdr.ip.hdr.dscp = hdr.shim.hdr.dscp;
            }
        }
        goto deparser;
    }
deparser: {
        __u32 outHeaderLengthInBytes = 0;
        outHeaderLengthInBytes += sizeof(hdr.ethernet.hdr) * hdr.ethernet.valid;
        outHeaderLengthInBytes += sizeof(hdr.vlan.hdr) * hdr.vlan.valid;
        outHeaderLengthInBytes += sizeof(hdr.qinq.hdr) * hdr.qinq.valid;
        outHeaderLengthInBytes += sizeof(hdr.ip.hdr) * hdr.ip.valid;
        outHeaderLengthInBytes += sizeof(hdr.udp.hdr) * hdr.udp.valid;
        outHeaderLengthInBytes += sizeof(hdr.tcp.hdr) * hdr.tcp.valid;
        if (bpf_xdp_adjust_head(ctx, packetOffsetInBytes - outHeaderLengthInBytes)) { goto reject; }
        packetStart = ((void*)(long)ctx->data);
        packetEnd = ((void*)(long)ctx->data_end);
        packetOffsetInBytes = 0;
        if (hdr.ethernet.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.ethernet.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.ethernet.hdr, sizeof(hdr.ethernet.hdr));
            packetOffsetInBytes += sizeof(hdr.ethernet.hdr);
        }
        if (hdr.vlan.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.vlan.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.vlan.hdr, sizeof(hdr.vlan.hdr));
            packetOffsetInBytes += sizeof(hdr.vlan.hdr);
        }
        if (hdr.qinq.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.qinq.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.qinq.hdr, sizeof(hdr.qinq.hdr));
            packetOffsetInBytes += sizeof(hdr.qinq.hdr);
        }
        if (hdr.ip.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.ip.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.ip.hdr, sizeof(hdr.ip.hdr));
            packetOffsetInBytes += sizeof(hdr.ip.hdr);
        }
        if (hdr.udp.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.udp.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.udp.hdr, sizeof(hdr.udp.hdr));
            packetOffsetInBytes += sizeof(hdr.udp.hdr);
        }
        if (hdr.tcp.valid)
        {
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(hdr.tcp.hdr)) { goto reject; }
            memcpy(packetStart + packetOffsetInBytes, &hdr.tcp.hdr, sizeof(hdr.tcp.hdr));
            packetOffsetInBytes += sizeof(hdr.tcp.hdr);
        }
        goto pass;
    }
}

char _license[] SEC("license") = "GPL";