#ifndef __FILTER_DEFS_H__
#define __FILTER_DEFS_H__

#include <linux/types.h>
#include <asm/byteorder.h>

// Map Keys

struct flow_key {
    __u32 switch_id;
    __u16 egress_port;
    __u16 vlan_id;
};

struct hop_key {
    struct flow_key flow_key;
    __u32 hop_index;
};

// Map Values

struct counter_set {
    __u64 packets;
    __u64 bytes;
};

struct flow_thresholds {
    __u32 hop_latency_threshold;
    __u32 hop_latency_delta;
    __u32 sink_time_threshold;
    __u32 sink_time_delta;
    __u32 total_hops;
};

struct hop_thresholds {
    __u32 hop_latency_threshold;
    __u32 hop_latency_delta;
    __u32 queue_occupancy_threshold;
    __u32 queue_occupancy_delta;
    __u32 switch_id;
};

#endif