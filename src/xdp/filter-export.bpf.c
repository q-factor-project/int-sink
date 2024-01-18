//#include "export.h"
#include <shared/filter_defs.h>
#include "export.h"

//#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include "helpers.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct flow_key);
    __type(value, struct counter_set);
} flow_counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct flow_key);
    __type(value, struct flow_thresholds);
} flow_thresholds_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct hop_key);
    __type(value, struct hop_thresholds);
} hop_thresholds_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_output_map SEC(".maps");

#define MAX_HOPS 20

#define ABS(a, b) ((a>b)? (a-b):(b-a))

int export_int_metadata(struct xdp_md *ctx, __u16 vlan_id, __u64 metadata_length_and_pInfo, __u64 packet_size, __u64 vSocket_Ipinfo)
{
    void* packetStart = (void*)(long)ctx->data;
    void* packetEnd = (void*)(long)ctx->data_end;
    unsigned packetOffsetInBytes = 0;
    __u16 metadata_length = metadata_length_and_pInfo;
    __u32 vPorts = metadata_length_and_pInfo >> 32;
    __u16 metadata_remaining = metadata_length;
    __u32 total_hop_latency = 0;
    __u32 flow_sink_time = 0;
    struct hop_key hop_key = { {0, 0, vlan_id}, 0};
    goto parse_metadata;
reject: { return -1; }
parse_metadata: { // Read the first element to finish the flow key
        for (int i = 0; i < MAX_HOPS; i++)
        {
            if (metadata_remaining < sizeof(struct int_hop_metadata)) { goto evaluate_flow; }
            if (packetEnd < packetStart + packetOffsetInBytes + sizeof(struct int_hop_metadata)) { goto reject; }
            struct int_hop_metadata* hop_metadata_ptr = packetStart + packetOffsetInBytes;
            packetOffsetInBytes += sizeof(struct int_hop_metadata);
            metadata_remaining -= sizeof(struct int_hop_metadata);
	    hop_key.flow_key.src_ip = (vSocket_Ipinfo  >> 32);
	    hop_key.flow_key.dst_ip = (vSocket_Ipinfo & 0xFFFFFFFF);
	    hop_key.flow_key.src_port = vPorts >> 16; 
	    hop_key.flow_key.dst_port = vPorts & 0xFFFF;
            if (hop_key.hop_index == 0)
            {
                // Complete the flow key
                hop_key.flow_key.egress_port = bpf_ntohs(hop_metadata_ptr->egress_port_id);
                hop_key.flow_key.switch_id = bpf_ntohl(hop_metadata_ptr->switch_id);
                flow_sink_time = bpf_ntohl(hop_metadata_ptr->ingress_time);
                // Count packets per flow
                struct counter_set *counter_set_ptr = bpf_map_lookup_elem(&flow_counters_map, &(hop_key.flow_key));
                if (!counter_set_ptr) { goto export; } // Unknown flow, pass to update
                __sync_fetch_and_add(&(counter_set_ptr->packets), 1);
                __sync_fetch_and_add(&(counter_set_ptr->bytes), packet_size);
            }
            // Check thresholds
            struct hop_thresholds *hop_threshold_ptr = bpf_map_lookup_elem(&hop_thresholds_map, &hop_key);
            if (!hop_threshold_ptr) { goto export; } // Unknown, hop, pass to update
            if (bpf_ntohl(hop_metadata_ptr->switch_id) != hop_threshold_ptr->switch_id) { goto export; }
            if (ABS((bpf_ntohl(hop_metadata_ptr->queue_info) & 0xffffff), hop_threshold_ptr->queue_occupancy_threshold ) > hop_threshold_ptr->queue_occupancy_delta) { goto export; } 
            if (ABS((bpf_ntohl(hop_metadata_ptr->egress_time) - bpf_ntohl(hop_metadata_ptr->ingress_time)), hop_threshold_ptr->hop_latency_threshold ) > hop_threshold_ptr->hop_latency_delta) { goto export; }

            // Add values to accumulators
            total_hop_latency += bpf_ntohl(hop_metadata_ptr->egress_time) - bpf_ntohl(hop_metadata_ptr->ingress_time);
            hop_key.hop_index += 1;
        }
    }
evaluate_flow: {
        struct flow_thresholds *flow_threshold_ptr = bpf_map_lookup_elem(&flow_thresholds_map, &(hop_key.flow_key));
        if (!flow_threshold_ptr) { goto export; } // Unknown flow, pass to update
        if (ABS(total_hop_latency, flow_threshold_ptr->hop_latency_threshold) > flow_threshold_ptr->hop_latency_delta ) { goto export; }
        if ( (flow_sink_time - flow_threshold_ptr->sink_time_threshold) > flow_threshold_ptr->sink_time_delta ) { goto export; }
        if (hop_key.hop_index != flow_threshold_ptr->total_hops) { goto export; }
        goto accept;
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
