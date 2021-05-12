#ifndef __MOCK_LINUX_BPF_H__
#define __MOCK_LINUX_BPF_H__

struct xdp_md {
    void *data;
    void *data_end;
    void *data_meta;
};

#endif