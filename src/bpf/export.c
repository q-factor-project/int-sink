#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct counter_set));
    __uint(max_entries, 512);
} flow_counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} perf_output_map SEC(".maps");

int export_int_metadata(struct xdp_md *ctx, __u16 vlan_id, __u16 metadata_length, __u64 packet_size)
{
    void* packetStart = (void*)(long)ctx->data;
    void* packetEnd = (void*)(long)ctx->data_end;
    //unsigned packetOffsetInBytes = 0;
    struct hop_key hop_key = { {0, 0, vlan_id}, (metadata_length / sizeof(struct int_hop_metadata))};
    goto parse_metadata;
reject: { return -1; }
parse_metadata: { // Read the first element to finish the flow key
        if (metadata_length < sizeof(struct int_hop_metadata)) { goto reject; } // Need at least 1 valid hop
        if (packetEnd < packetStart /*+ packetOffsetInBytes*/ + sizeof(struct int_hop_metadata)) { goto reject; }
        struct int_hop_metadata* hop_metadata_ptr = packetStart /*+ packetOffsetInBytes*/;
        hop_key.flow_key.egress_port = bpf_ntohs(hop_metadata_ptr->egress_port_id);
        hop_key.flow_key.switch_id = bpf_ntohl(hop_metadata_ptr->switch_id);
        volatile struct counter_set *counter_set_ptr = bpf_map_lookup_elem(&flow_counters_map, &(hop_key.flow_key));
        if (!counter_set_ptr) { goto export; } // Unknown flow, pass to update
        __sync_fetch_and_add(&(counter_set_ptr->packets), 1);
        __sync_fetch_and_add(&(counter_set_ptr->bytes), packet_size);
        goto export;
    }
export: {
        __u64 perf_flags = BPF_F_CURRENT_CPU;
        __u16 sample_size = metadata_length;
        perf_flags |= (__u64)sample_size << 32;
        bpf_perf_event_output(ctx, &perf_output_map, perf_flags, &hop_key, sizeof(hop_key));
        goto accept;
    }
accept: {
        return 0;
    }
}