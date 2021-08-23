
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <getopt.h>
#include <unistd.h>
#include <signal.h>

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"interface", required_argument, NULL, 'i'},
    {"file", required_argument, NULL, 'f'},
    {"pin", required_argument, NULL, 'p'},
    {"force", no_argument, NULL, 'F'},
    {}
};
static const char usage_str[] =
"Program to attach an XDP program from an ELF file.\n"
"Usage: %s <options>\n"
"Required options:\n"
"       --interface,  -i <interface>  interface to attach XDP program to\n"
"       --file,       -f <file>       ELF file containing program to attach to interface\n"
"Optioinal options:\n"
"       --pin,        -p <directory>  directory to pin maps of XDP program to.\n"
"       --Force,      -F              force attaching the program to the desired interface\n"
"       --help,       -h              displays this menu\n";


static void interrupt_handler(int signum);
static int interrupted = 0;

int main(int argc , char **argv)
{
    char *if_name = NULL;
    char *pin_maps = NULL;
    
    int opt = 0;
    int arg_index = 0;

    int result;
    int prog_fd;
    struct bpf_object *bpf_obj_ptr;

    struct bpf_prog_load_attr prog_attributes = {
        .file = NULL,
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = 0,
        .prog_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_HW_MODE,
    };

    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);

    while ((opt = getopt_long(argc, argv, "i:f:p:Fh", long_options, &arg_index)) != -1)
    {
        switch (opt) {
        case 'i':
            if_name = optarg;
            prog_attributes.ifindex = if_nametoindex(if_name);
            if (!prog_attributes.ifindex)
            {
                fprintf(stderr, "ERROR: Invalid interface [%s]\n", if_name);
                return 1;
            }
            break;
        case 'f':
            prog_attributes.file = optarg;
            break;
        case 'p':
            pin_maps = optarg;
            break;
        default:
        case 'h':
            fprintf(stdout, usage_str, argv[0]);
            return 1;
        }
    }

    if(!prog_attributes.ifindex)
    {
        fprintf(stderr, "ERROR: Missing required option, interface");
        return 1;
    }

    if(!prog_attributes.file)
    {
        fprintf(stderr, "ERROR: Missing required option, file");
        return 1;
    }

    int error = 0;

    result = bpf_prog_load_xattr(&prog_attributes, &bpf_obj_ptr, &prog_fd);

    if (result)
    {
        fprintf(stderr, "ERROR: Failed to load program [%s] onto interface [%s]\n", prog_attributes.file, if_name);
        error = 1;
        goto CLOSE_APP;
    }

    if (pin_maps)
    {
        result = bpf_object__pin_maps(bpf_obj_ptr, pin_maps);
        if (result)
        {
            fprintf(stderr, "ERROR: Failed to pin maps to [%s]\n", pin_maps);
            error = 1;
            goto UNLOAD_PROG;
        }
    }

    fprintf(stdout, "XDP program loading completed.\n");
    if (!interrupted)
    {
        fprintf(stdout, "User space application entering pause state...\n");
        pause();
    }
    fprintf(stdout, "Closing application.\n");

UNLOAD_MAPS:

    if (pin_maps)
    {
        result = bpf_object__unpin_maps(bpf_obj_ptr, pin_maps);
        if(result)
        {
            fprintf(stderr, "ERROR: Failed to unpin maps from [%s]\n", pin_maps);
            error = 1;
        }
    }

UNLOAD_PROG:

    result = bpf_object__unload(bpf_obj_ptr);

    if (result)
    {
        fprintf(stderr, "ERROR: Failed to unload object.\n");
        error = 1;
    }

CLOSE_APP:

    return error;
}

static void interrupt_handler(int signum)
{
    fprintf(stdout, "Received interrupt [%d].\n", signum);
    interrupted = 1;
}