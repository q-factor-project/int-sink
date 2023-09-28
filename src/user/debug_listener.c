#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

enum ARGS{
    CMD_ARG,
    BPF_MAPS_DIR_ARG,
    MAX_ARG_COUNT
};

#define PERF_PAGE_COUNT 512

struct sample_ctx {
    FILE *out_file;
};

void sample_func(struct sample_ctx *ctx, int cpu, void *data, __u32 size);
void lost_func(struct sample_ctx *ctx, int cpu, __u64 cnt);

enum {
    ARG_CMD,
    ARG_PERF_LOC,
    ARG_END
};

int main(int argc, char **argv)
{
    int perf_debug_map;
    struct perf_buffer *pb;
    struct sample_ctx ctx = {
        stdout
    };
process_args: {
        if (argc != ARG_END)
        {
            fprintf(
                stderr,
                "ERROR: The amount of args given (%d) did not match the expected (%d).\n",
                argc,
                ARG_END
            );
            return -1;
        }
    }
open_maps: {
        fprintf(stderr, "Opening maps.\n");
        fprintf(stderr, "Getting perf_debug_map.\n");
        perf_debug_map = bpf_obj_get(argv[ARG_PERF_LOC]);
        if (perf_debug_map < 0) {
            fprintf(
                stderr,
                "ERROR: Failed to get the perf buffer from (%s).\n",
                argv[ARG_PERF_LOC]
            );
            goto close_maps; 
        }
    }
open_perf_event: {
        fprintf(stderr, "Opening perf event buffer.\n");
        struct perf_buffer_opts opts = {
            (perf_buffer_sample_fn)sample_func,
            (perf_buffer_lost_fn)lost_func,
            &ctx
        };
        pb = perf_buffer__new(
            perf_debug_map,
            PERF_PAGE_COUNT, 
            &opts
        );
        if (pb == 0) {
            fprintf(
                stderr,
                "ERROR: Failed to open the perf buffer for reading.\n"
            );
            goto close_maps;
        }
    }
perf_event_loop: {
        fprintf(stderr, "Running perf event loop.\n");
        int err = 0;
        do {
            err = perf_buffer__poll(pb, 500);
        }
        while(err >= 0);
        fprintf(stderr, "Exited perf event loop with err %d.\n", -err);
    }
close_maps: {
        fprintf(stderr, "Closing maps.\n");
        if (perf_debug_map <= 0) { goto exit_program; }
        close(perf_debug_map);
        if (pb == 0) { goto exit_program; }
        perf_buffer__free(pb);
    }
exit_program: {
        return 0;
    }
}

void sample_func(struct sample_ctx *ctx, int cpu, void *data, __u32 size)
{
    void *data_end = data + size;
    fprintf(ctx->out_file, "Received Packet: ");
    for (void *data_ptr = data; data_ptr + sizeof(char) <= data_end; data_ptr += sizeof(char)) {
        fprintf(ctx->out_file, "%02hhx", *(char*)data_ptr);
    }
    fprintf(ctx->out_file, "\n");
}

void lost_func(struct sample_ctx *ctx, int cpu, __u64 cnt)
{
    fprintf(stderr, "Missed %llu packets.\n", cnt);
}