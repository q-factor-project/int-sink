#include <xdp/int_remover.skel.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>
#include "sample_processor.h"

// Arguments + Usage

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"interface", required_argument, NULL, 'i'},
    {"pin", required_argument, NULL, 'p'},
    {"Force", no_argument, NULL, 'F'},
    {"skb", no_argument, NULL, 's'},
};

static const char usage_str[] =
"XDP program to remove In-Band Network Telemetry(INT) data from packets on interface ingress.\n"
"Usage: %s <options>\n"
"Required options:\n"
"       --interface,  -i  <interface>  interface to attach XDP program to\n"
"Optional options:\n"
"       --pin,        -p  <file>       location to pin INT ring buffer to.\n"
"       --Force,      -F               force loading program\n"
"       --skb         -s               load in socket buffer mode\n"
"       --help,       -h               display this menu\n";

//Function prototypes

static void interrupt_handler(int signum);

// Global variables

static int ifindex = 0;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static struct int_remover_bpf *obj;
static __u32 prog_id;
static char *map_pin;

// Main function

int main(int argc, char **argv)
{

    int err = 0;

    int prog_fd;

    struct bpf_prog_info info = {};
    unsigned int info_len = sizeof(info);

    char *if_name;

    struct ring_buffer *int_ringbuf = NULL;
    int rb_fd;

    int do_pin_map = 0;

    int opt = 0;
    int arg_index = 0;
    while ((opt = getopt_long(argc, argv, "i:p:Fsh", long_options, &arg_index)) != -1)
    {
        switch (opt) {
        case 'i':
            if_name = optarg;
            ifindex = if_nametoindex(if_name);
            if(!ifindex)
            {
                fprintf(stderr, "ERROR: Invalid interface %s\n", if_name);
                return 1;
            }
            break;
        case 'p':
            do_pin_map = 1;
            map_pin = optarg;
            break;
        case 'F':
            xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 's':
             xdp_flags |= XDP_FLAGS_SKB_MODE;
             break;
        default:
        case 'h':
            fprintf(stdout, usage_str, argv[0]);
            return 1;
        }
    }

    if (ifindex == 0) {
        fprintf(stderr, "ERROR: Missing required option, interface\n");
        return 1;
    }

    if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
        xdp_flags |= XDP_FLAGS_DRV_MODE;

    struct rlimit memlock_limit = { RLIM_INFINITY, RLIM_INFINITY };

    err = setrlimit(RLIMIT_MEMLOCK, &memlock_limit);
    if(err)
    {
        fprintf(stderr, "ERROR: Failed to set locked memory limit\n");
    }

    obj = int_remover_bpf__open_and_load();

    if(!obj)
    {
        fprintf(stderr, "ERROR: Failed to open and load program.\n");
        return 1;
    }

    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);

    struct sampler_context int_context = {
        .buffer_name = "INT",
        .stream = stdout,
    };

    if(!do_pin_map) {
        int_ringbuf = ring_buffer__new(bpf_map__fd(obj->maps.int_ring_buffer), read_buffer_sample, &int_context, NULL);

        if(!int_ringbuf) {
            fprintf(stderr, "ERROR: Failed to attach sampler to ring buffer.\n");
            goto CLEANUP;
        }
    }

    if(do_pin_map) {
        err = bpf_map__pin(obj->maps.int_ring_buffer, map_pin);

        if (err) {
            fprintf(stderr, "ERROR: Failed to pin ring buffer.\n");
            goto CLEANUP;
        }
    }

    prog_fd = bpf_program__fd(obj->progs.driver);

    if(!prog_fd)
    {
        fprintf(stderr, "ERROR: Failed to retrieve program file descriptor.\n");
        goto CLEANUP;
    }

    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err)
    {
        fprintf(stderr, "ERROR: Failed to attach program to interface %s.\n", if_name);
        goto CLEANUP;
    }

    err = int_remover_bpf__attach(obj);

    if (err)
    {
        fprintf(stderr, "ERROR: Failed to attach BPF.\n");
        goto CLEANUP;
    }

    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERROR: Failed to retrieve program info.\n");
		return 1;
	}
	prog_id = info.id;

    printf("Fully attached\n");

    if (!do_pin_map) {
        while(err >= 0)
        {
            err = ring_buffer__consume(int_ringbuf);
        }
    }
    if (do_pin_map) {
        pause();
    }
    

CLEANUP:
    interrupt_handler(0);
    return 0;
}

// Function Definitions

static void interrupt_handler(int signum)
{
    printf("Cleaning up\n");
    printf("Packets processed: %d\n", obj->bss->counter);
    printf("Packets dropped: %d\n", obj->bss->dropped);
    printf("INT processed: %d\n", obj->bss->int_counter);
    __u32 curr_prog_id;
    if (ifindex > -1) {
		if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
			printf("bpf_get_link_xdp_id failed\n");
			exit(1);
		}
		if (prog_id == curr_prog_id)
			bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		else if (!curr_prog_id)
			printf("couldn't find a prog id on a given iface\n");
		else
			printf("program on interface changed, not removing\n");
	}
    if(bpf_map__is_pinned(obj->maps.int_ring_buffer))
        bpf_map__unpin(obj->maps.int_ring_buffer, map_pin);
    int_remover_bpf__destroy(obj);
	exit(0);
}