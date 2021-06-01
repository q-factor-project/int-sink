
struct _IO_FILE;

typedef struct _IO_FILE FILE;

struct sampler_context
{
    FILE * stream;
    char buffer_name[16];
};

int read_buffer_sample(void *output_stream, void *data, unsigned long length);