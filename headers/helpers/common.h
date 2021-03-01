#ifndef HELPERS_COMMON_H
#define HELPERS_COMMON_H

#include <asm/byteorder.h>
#include <stddef.h>
#include <arpa/inet.h>

struct hdr_cursor {
    void * start;
    void * pos;
    void * end;
};

#endif