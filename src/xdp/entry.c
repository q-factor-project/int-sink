#include "process.h"

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;
int dropped = 0;

/*
 * Entry point into xdp program.
 */
SEC("xdp")
__u32 entry(struct xdp_md *ctx)
{
    counter++;
    __u32 result = driver(ctx);
    switch(result)
    {
    case XDP_PASS:
        break;
    default:
    case XDP_DROP:
        dropped++;
        break;
    }
    return result;
}