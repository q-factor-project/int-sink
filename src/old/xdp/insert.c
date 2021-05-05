#include "insert.h"
#include <linux/bpf.h>

#define MAX_BUFFER_SIZE 60UL

__u32 insert_from_buffer(struct xdp_md *ctx, void *buffer, __u32 size)
{
    __u32 *pos = ctx->data;
    __u32 *buf = buffer;

    if (ctx->data + size > ctx->data_end)
        return -1;
    
    for(int i = 0; i < MAX_BUFFER_SIZE; i += sizeof(*buf))
    {
        if (pos + 1 > ctx->data_end) // Double check required by verifier
        {
            break;
        }
        if (i >= size)
        {
            break;
        }
        *pos = *buf;
        buf += 1;
        pos += 1;
    }
    return 0;
}

__u32 extract_to_buffer(struct xdp_md *ctx, void *buffer, __u32 size)
{
    __u32 *pos = ctx->data;
    __u32 *buf = buffer;

    if (ctx->data + size > ctx->data_end)
        return -1;
    
    for(int i = 0; i < MAX_BUFFER_SIZE; i += sizeof(*buf))
    {
        if (pos + 1 > ctx->data_end) // Double check required by verifier
        {
            break;
        }
        if (i >= size)
        {
            break;
        }
        *buf = *pos;
        buf += 1;
        pos += 1;
    }
    return 0;
}