#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <shared/int_defs.h>
#include <shared/filter_defs.h>

enum ARGS{
    CMD_ARG,
    BPF_MAPS_DIR_ARG,
    MAX_ARG_COUNT
};

struct threshold_maps
{
    int flow_thresholds;
    int hop_thresholds;
    int flow_counters;
};

#define MAP_DIR "/sys/fs/bpf/test_maps"
#define HOP_LATENCY_DELTA 20000
#define FLOW_LATENCY_DELTA 50000
#define QUEUE_OCCUPANCY_DELTA 80
#define FLOW_SINK_TIME_DELTA 1000000000

#define INT_DSCP (0x17)

#define PERF_PAGE_COUNT 512
#define MAX_FLOW_COUNTERS 512

void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size);
void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt);
void print_hop_key(struct hop_key *key);

int main(int argc, char **argv)
{
    int perf_output_map;
    int int_dscp_map;
    struct perf_buffer *pb;
    struct threshold_maps maps = {};
open_maps: {
        fprintf(stdout, "Opening maps.\n");
        //maps.counters = bpf_obj_get(MAP_DIR "/counters_map");
        fprintf(stdout, "Opening flow_counters_map.\n");
        maps.flow_counters = bpf_obj_get(MAP_DIR "/flow_counters_map");
        if (maps.flow_counters < 0) { goto close_maps; }
        fprintf(stdout, "Opening flow_thresholds_map.\n");
        maps.flow_thresholds = bpf_obj_get(MAP_DIR "/flow_thresholds_map");
        if (maps.flow_thresholds < 0) { goto close_maps; }
        fprintf(stdout, "Opening hop_thresholds_map.\n");
        maps.hop_thresholds = bpf_obj_get(MAP_DIR "/hop_thresholds_map");
        if (maps.hop_thresholds < 0) { goto close_maps; }
        fprintf(stdout, "Opening perf_output_map.\n");
        perf_output_map = bpf_obj_get(MAP_DIR "/perf_output_map");
        if (perf_output_map < 0) { goto close_maps; }
        fprintf(stdout, "Opening int_dscp_map.\n");
        int_dscp_map = bpf_obj_get(MAP_DIR "/int_dscp_map");
        if (int_dscp_map < 0) { goto close_maps; }
    }
set_int_dscp: {
        fprintf(stdout, "Setting INT DSCP.\n");
        __u32 int_dscp = INT_DSCP;
        __u32 zero_value = 0;
        bpf_map_update_elem(int_dscp_map, &int_dscp, &zero_value, BPF_NOEXIST);
    }
open_perf_event: {
        fprintf(stdout, "Opening perf event buffer.\n");
        struct perf_buffer_opts opts = {
            (perf_buffer_sample_fn)sample_func,
            (perf_buffer_lost_fn)lost_func,
            &maps
        };
        pb = perf_buffer__new(perf_output_map, PERF_PAGE_COUNT, &opts);
        if (pb == 0) { goto close_maps; }
    }
perf_event_loop: {
        fprintf(stdout, "Running perf event loop.\n");
        int err = 0;
        do {
            err = perf_buffer__poll(pb, 500);
        }
        while(err >= 0);
        fprintf(stdout, "Exited perf event loop with err %d.\n", -err);
    }
close_maps: {
        fprintf(stdout, "Closing maps.\n");
        if (maps.flow_counters <= 0) { goto exit_program; }
        close(maps.flow_counters);
        if (maps.flow_thresholds <= 0) { goto exit_program; }
        close(maps.flow_thresholds);
        if (maps.hop_thresholds <= 0) { goto exit_program; }
        close(maps.hop_thresholds);
        if (perf_output_map <= 0) { goto exit_program; }
        close(perf_output_map);
        if (int_dscp_map <= 0) { goto exit_program; }
        close(int_dscp_map);
        if (pb == 0) { goto exit_program; }
        perf_buffer__free(pb);
    }
exit_program: {
        return 0;
    }
}

void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size)
{
    void *data_end = data + size;
    __u32 data_offset;
    struct hop_key hop_key;
    if(data + data_offset + sizeof(hop_key) > data_end) return;
    memcpy(&hop_key, data + data_offset, sizeof(hop_key));
    data_offset += sizeof(hop_key);
    struct flow_thresholds flow_threshold_update = {
        0,
        FLOW_LATENCY_DELTA,
        0,
        FLOW_SINK_TIME_DELTA,
        0
    };
    hop_key.hop_index = 0;
    while (data + data_offset + sizeof(struct int_hop_metadata) <= data_end)
    {
        struct int_hop_metadata *hop_metadata_ptr = data + data_offset; 
        data_offset += sizeof(struct int_hop_metadata);
        struct hop_thresholds hop_threshold_update = {
            ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time),
            HOP_LATENCY_DELTA,
            ntohl(hop_metadata_ptr->queue_info) & 0xffffff,
            QUEUE_OCCUPANCY_DELTA,
            ntohl(hop_metadata_ptr->switch_id)
        };
        bpf_map_update_elem(ctx->hop_thresholds, &hop_key, &hop_threshold_update, BPF_ANY);
        if(hop_key.hop_index == 0) { flow_threshold_update.sink_time_threshold = ntohl(hop_metadata_ptr->ingress_time); }
        flow_threshold_update.hop_latency_threshold += ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time);
        print_hop_key(&hop_key);
        hop_key.hop_index++;
    }
    flow_threshold_update.total_hops = hop_key.hop_index;
    bpf_map_update_elem(ctx->flow_thresholds, &hop_key.flow_key, &flow_threshold_update, BPF_ANY);
    struct counter_set empty_counter = {};
    bpf_map_update_elem(ctx->flow_counters, &(hop_key.flow_key), &empty_counter, BPF_NOEXIST);
}

void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt)
{
    fprintf(stderr, "Missed %llu sets of packet metadata.\n", cnt);
}

void print_flow_key(struct flow_key *key)
{
    fprintf(stdout, "Flow Key:\n");
    fprintf(stdout, "\tegress_switch:%X\n", key->switch_id);
    fprintf(stdout, "\tegress_port:%hu\n", key->egress_port);
    fprintf(stdout, "\tvlan_id:%hu\n", key->vlan_id);
}

void print_hop_key(struct hop_key *key)
{
    fprintf(stdout, "Hop Key:\n");
    print_flow_key(&(key->flow_key));
    fprintf(stdout, "\thop_index: %X\n", key->hop_index);
}