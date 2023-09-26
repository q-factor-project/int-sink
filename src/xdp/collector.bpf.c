#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include "export.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct counter_set));
    __uint(max_entries, 2);
} counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
} int_collector_ports_map SEC(".maps");

int ebpf_filter(struct xdp_md *ctx) {
    unsigned packetOffsetInBytes = 0;
    void* packetStart = (void*)(long)ctx->data;
    void* packetEnd = (void*)(long)ctx->data_end;
    __u64 vSrc_Socket = 0;
    __u64 packetSize = packetEnd - packetStart;
    __u16 vlan_id = 0;
    __u32 metadata_length;
    goto start;
    reject: { return XDP_DROP; }
    pass: { return XDP_PASS; }
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
        packetOffsetInBytes += sizeof(struct ethhdr);
        switch (eth_ptr->h_proto) {
            case bpf_htons(ETH_P_IP): goto parse_ipv4;
            case bpf_htons(ETH_P_8021Q): goto parse_vlan;
            default: goto pass;
        }
    }
parse_vlan: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct vlanhdr)) { goto reject; }
        struct vlanhdr* vlan_ptr = packetStart + packetOffsetInBytes;
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
        packetOffsetInBytes += sizeof(struct vlanhdr);
        switch (vlan_ptr->h_proto) {
            case bpf_htons(ETH_P_IP): goto parse_ipv4;
            default: goto pass;
        }
    }
parse_ipv4: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct iphdr)) { goto reject; }
        struct iphdr* ip_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct iphdr);
        switch (ip_ptr->protocol) {
            case 0x11: goto parse_udp;
            default: goto pass;
        }
    }
parse_udp: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct udphdr)) { goto reject; }
        struct udphdr* udp_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct udphdr);
        __u32 in_port = bpf_ntohs(udp_ptr->dest);
        if (bpf_map_lookup_elem(&int_collector_ports_map, &in_port)) { goto parse_telemetry_report; }
        goto pass;
    }
parse_telemetry_report: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct telemetry_report_v10_t)) { goto reject; }
        //struct telemetry_report_v10_t* telemetry_report_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct telemetry_report_v10_t);
        goto parse_inner;
    }
parse_inner: {
        goto parse_inner_ether;
    }
parse_inner_ether: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct ethhdr)) { goto reject; }
        struct ethhdr* eth_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct ethhdr);
        switch (eth_ptr->h_proto) {
            case bpf_htons(ETH_P_8021Q): goto parse_inner_vlan;
            case bpf_htons(ETH_P_IP): goto parse_inner_ipv4;
            default: goto reject;
        }
    }
parse_inner_vlan: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct vlanhdr)) { goto reject; }
        struct vlanhdr* vlan_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct vlanhdr);
        vlan_id = bpf_ntohs(vlan_ptr->h_vlan_tag);
        switch (vlan_ptr->h_proto) {
            case bpf_htons(ETH_P_8021Q): goto parse_inner_qinq;
            case bpf_htons(ETH_P_IP): goto parse_inner_ipv4;
            default: goto reject;
        }
    }
parse_inner_qinq: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct vlanhdr)) { goto reject; }
        struct vlanhdr* vlan_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct vlanhdr);
        switch (vlan_ptr->h_proto) {
            case bpf_htons(ETH_P_IP): goto parse_inner_ipv4;
            default: goto reject;
        }
    }
parse_inner_ipv4: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct iphdr)) { goto reject; }
        struct iphdr* ip_ptr = packetStart + packetOffsetInBytes;
	vSrc_Socket =  (vSrc_Socket + bpf_ntohl(ip_ptr->saddr)) << 32;
        packetOffsetInBytes += sizeof(struct iphdr);
        switch (ip_ptr->protocol) {
            case 0x6: goto parse_inner_tcp;
            case 0x11: goto parse_inner_udp;
            default: goto reject;
        }
    }
parse_inner_udp: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct udphdr)) { goto reject; }
        //struct udphdr* udp_ptr = packetStart + packetOffsetInBytes;
        packetOffsetInBytes += sizeof(struct udphdr);
        goto parse_shim;
    }
parse_inner_tcp: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct tcphdr)) { goto reject; }
        struct tcphdr* tcp_ptr = packetStart + packetOffsetInBytes;
        vSrc_Socket += bpf_ntohs(tcp_ptr->source);
        packetOffsetInBytes += sizeof(struct tcphdr);
        goto parse_shim;
    }
parse_shim: {
        if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct int10_shim_t)) { goto reject; }
        struct int10_shim_t* shim_ptr = packetStart + packetOffsetInBytes;
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
        if (export_int_metadata(ctx, vlan_id, metadata_length, packetSize, vSrc_Socket)) { goto reject; };
        packetOffsetInBytes = metadata_length;
        __u32 key = 1; // Count int packets received
        struct counter_set *counter_set_ptr = bpf_map_lookup_elem(&counters_map, &key);
        if (counter_set_ptr)
        {
            __sync_fetch_and_add(&(counter_set_ptr->packets), 1);
            __sync_fetch_and_add(&(counter_set_ptr->bytes), packetSize);
        }
        goto accept;
    }
accept: {
        goto reject;
    }
}

char _license[] SEC("license") = "GPL";
