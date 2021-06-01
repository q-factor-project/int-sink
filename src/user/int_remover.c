
#include <xdp/int_remover.skel.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "sample_processor.h"

// Types

enum ARGS
{
    COMMAND_ARG=0,
    INTERFACE_ARG,
    ARG_COUNT,
};

//Function prototypes

static void interrupt_handler(int signum);

// Global variables

int interrupt = 0;

// Main function

int main(int argc, char **argv)
{
    struct int_remover_bpf *obj;
    int ifindex;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    int err = 0;
    
    int prog_fd;
    char *if_name;
    struct ring_buffer *int_ringbuf;
    
    fprintf(stdout, "Parsing arguments.\n");

    if (argc != ARG_COUNT)
    {
        fprintf(stderr, "Invalid argument count, expected %d, got %d.\n", ARG_COUNT, argc);
        return 1;
    }

    if_name = argv[INTERFACE_ARG];

    fprintf(stdout, "Validating interface %s.\n", if_name);

    ifindex = if_nametoindex(if_name);

    if(ifindex < 0)
    {
        fprintf(stderr, "Interface %s is invalid.\n", if_name);
        return 1;
    }

    fprintf(stdout, "Finished parsing arguments.\n");

    fprintf(stdout, "Setting signal handler.\n");
    if(signal(SIGINT, interrupt_handler) == SIG_ERR)
    {
        fprintf(stderr, "Failed to set signal handler.");
        return 1;
    }

    fprintf(stdout, "Openining int remover bpf\n");
    obj = int_remover_bpf__open_and_load();

    if(!obj)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton.\n");
        err = -1;
        goto CLEANUP;
    }
    
    fprintf(stdout, "Retrieving ring buffer.\n");

    struct sampler_context int_context = {
        .buffer_name = "INT",
        .stream = stdout,
    };

    int_ringbuf = ring_buffer__new(bpf_map__fd(obj->maps.int_ring_buffer), read_buffer_sample, &int_context, NULL);

    if(!int_ringbuf) {
        fprintf(stderr, "Failed to retrieve ring buffer.\n");
        goto CLEANUP;
    }

    fprintf(stdout, "Retrieving program file descriptor.\n");
    prog_fd = bpf_program__fd(obj->progs.driver);

    if(!prog_fd)
    {
        fprintf(stderr, "Failed to retrieve program file descriptor.\n");
        goto CLEANUP;
    }

    fprintf(stdout, "Attaching program to interface %s.\n", if_name);
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err)
    {
        fprintf(stderr, "Failed to attach program to interface %s.\n", if_name);
        goto CLEANUP;
    }

    fprintf(stdout, "Attaching BPF skeleton.\n");
    err = int_remover_bpf__attach(obj);

    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton.\n");
        goto XDP_DETACH;
    }

    printf("Fully attached\n");

    while(err >= 0 && !interrupt)
    {
        err = ring_buffer__consume(int_ringbuf);
    }

XDP_DETACH:
    // Detach XDP program from interface
    fprintf(stdout, "Cleaning up\n");
    fprintf(stdout, "Packets processed: %d\n", obj->bss->counter);
    fprintf(stdout, "Packets dropped: %d\n", obj->bss->dropped);
    fprintf(stdout, "INT processed: %d\n", obj->bss->int_counter);
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
CLEANUP:
    int_remover_bpf__destroy(obj);
    return 0;
}

// Function Definitions

static void interrupt_handler(int signum)
{
    fprintf(stdout, "Received interrupt signal: %d\n", signum);
    interrupt = 1;
}