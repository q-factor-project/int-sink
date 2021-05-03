
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

enum ARGS
{
    COMMAND_ARG=0,
    FILENAME_ARG,
    INTERFACE_ARG,
    ARG_COUNT,
};


int main(int argc, char **argv)
{
    if (argc != ARG_COUNT)
    {
        fprintf(stderr, "Invalid argument count");
        return -1;
    }

    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    char *filename = argv[FILENAME_ARG];
    char *if_name = argv[INTERFACE_ARG];
    int ifindex = if_nametoindex(if_name);
    
    
    int prog_fd, err;
    struct bpf_obj *obj;
    struct bpf_prog_info info = {};
    int info_len = sizeof(info);


    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);

    if (err)
    {
        fprintf(stderr, "Failed to load BPF object file %s\n", filename);
        return err;
    }

    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err)
    {
        fprintf(stderr, "Failed to attach to link %s\n", if_name);
        return err;
    }

    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);

    if (err)
    {
        fprintf(stderr, "Failed to fetch program info\n");
        return err;
    }

    fprintf(stdout, "Successfully loaded:\n\tName: %s\n\tID: %d\n",
                    info.name, info.id);

    return 0;
}