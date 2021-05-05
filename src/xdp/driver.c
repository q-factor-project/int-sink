#include "process.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int int_counter = 0;
int counter = 0;
int dropped = 0;

SEC("xdp")
int remove_int(struct xdp_md *ctx)
{
    counter++;
    __u32 result;
    result = process_ether(ctx);
    switch(result) {
    case NO_ERR:// INT PACKET
        int_counter++;
        return XDP_PASS;
    case NONFATAL_ERR:// NON-INT PACKET
        return XDP_PASS;
    case FATAL_ERR://FATAL ERROR, SHOULD DROP
    default:
        dropped++;
        return XDP_DROP;
    }
}