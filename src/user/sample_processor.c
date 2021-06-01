#include "sample_processor.h"
#include <stdio.h>

int read_buffer_sample(void *sampler_context, void *data, unsigned long length)
{
    struct sampler_context *ctx = sampler_context;
    unsigned char *data_ptr = data;
    fprintf(ctx->stream, "[%s]Ringbuffer received %zu bytes.\n", ctx->buffer_name, length);
    fprintf(ctx->stream, "[%s]Ringbuffer contents:\n",ctx->buffer_name);
    for (int i = 0; i < length / sizeof(*data_ptr); i++) fprintf(ctx->stream, "%02x ", data_ptr[i]);
    fprintf(ctx->stream, "\n");
    return 0;
}