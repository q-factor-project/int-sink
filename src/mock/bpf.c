#include "mock/bpf.h"

long bpf_xdp_adjust_head(struct xdp_md *ctx, int offset)
{
    ctx->data += offset;
    return 0;
}

__s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed)
{
    __u64 diff_size = from_size + to_size;
    int i = 0, j = 0;
    __u64 sum = seed;
    for (i = 0; i < from_size / sizeof(__be32); i++)
    {
        sum += ~from[i];
    }
    for (i = 0; i < to_size / sizeof(__be32); i++)
    {
        sum += to[i];
    }
    
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return sum;
}