#ifndef MOCK_TYPES_XDP_H
#define MOCK_TYPES_XDP_H

struct xdp_md {
    void* data;
    void* data_end;
};

#endif