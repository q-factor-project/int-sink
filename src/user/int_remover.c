
#include <xdp/int_remover.skel.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>

// Global variables

struct int_remover_bpf *obj;
int ifindex;
__u32 xdp_flags;

// Types

enum ARGS
{
    COMMAND_ARG=0,
    INTERFACE_ARG,
    ARG_COUNT,
};

//Function prototypes

static void cleanup();

static void interrupt_handler(int signum);

// Main function

int main(int argc, char **argv)
{
    int err = 0;
    
    int prog_fd;
    char *if_name;
    
    fprintf(stderr, "Parsing arguments\n");

    if (argc != ARG_COUNT)
    {
        fprintf(stderr, "Invalid argument count\n");
        return 1;
    }

    if_name = argv[INTERFACE_ARG];
    ifindex = if_nametoindex(if_name);

    if(ifindex < 0)
    {
        fprintf(stderr, "Invalid interface: %s\n", if_name);
        return 1;
    }

    fprintf(stderr, "Arguments parsed\n");

    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);

    fprintf(stderr, "Openining int remover bpf\n");

    obj = int_remover_bpf__open();

    if(!obj)
    {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        err = -1;
        goto CLEANUP;
    }
    
    // TODO: Attach maps

    fprintf(stderr, "Loading int remover bpf\n");

    err = int_remover_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto CLEANUP;
    }

    fprintf(stderr, "Attaching int remover to %s\n", if_name);

    // Attach program to interface
    xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    prog_fd = bpf_program__fd(obj->progs.remove_int);
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err)
    {
        fprintf(stderr, "Failed to attach program to : %s.\n", if_name);
        goto CLEANUP;
    }

    err = int_remover_bpf__attach(obj);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto CLEANUP;
    }

    printf("Fully attached\n");

    pause();

CLEANUP:
    cleanup();
    return -err;
}

// Function Definitions

static void interrupt_handler(int signum)
{
    cleanup();
    exit(0);
}

static void cleanup()
{
    printf("Cleaning up\n");
    printf("Packets processed: %d\n", obj->bss->counter);
    printf("Packets dropped: %d\n", obj->bss->dropped);
    printf("INT processed: %d\n", obj->bss->int_counter);
    // Detach XDP program from interface
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    // Detach XDP program
    int_remover_bpf__detach(obj);
    // Destroy skeleton
    int_remover_bpf__destroy(obj);
}