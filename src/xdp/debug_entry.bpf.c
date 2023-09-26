#include <shared/filter_defs.h>
#include <shared/int_defs.h>
#include <shared/net_defs.h>
#include "export.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_debug_map SEC(".maps");

int ebpf_filter(struct xdp_md *ctx);

SEC("xdp")
int entry(struct xdp_md *ctx) {
    void* packetStart = (void*)(long)ctx->data;
    void* packetEnd = (void*)(long)ctx->data_end;
    __u32 packetLen = packetEnd - packetStart;
    if (packetLen < 128) {
        bpf_perf_event_output(ctx, &perf_debug_map, (__u64)packetLen << 32, &packetLen, 0);
    }
    return ebpf_filter(ctx);
}