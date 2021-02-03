#if !defined(__COMMON_HELPERS_H)
#define __COMMON_HELPERS_H

#include <asm/byteorder.h>
#include <stddef.h>
#include <arpa/inet.h>

struct hdr_cursor {
    void * pos;
};

struct ippseudohdr {
    __u32 saddr;
    __u32 daddr;
    __u8 reserved;
    __u8 protocol;
    __u16 body_length;
}__attribute((packed));

// Returns new checksum value when changing a value
// To be used with the values from checksum diff
/*
static __always_inline __u16 recalc_checksum(old_value, new_value, old_check)
{
    return old_check + ~new_value + old_value;
}
*/

#endif