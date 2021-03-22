#ifndef HELPERS_COMMON_H
#define HELPERS_COMMON_H

#include <asm/byteorder.h>
#include <stddef.h>

#ifdef __bpf__
#include <bpf/bpf_endian.h>
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#else
#include <arpa/inet.h>
#endif

struct hdr_cursor {
    void * start;
    void * pos;
    void * end;
};

#endif