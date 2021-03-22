#ifndef TYPES_IP_PSEUDO_H

#include <linux/types.h>

struct ippseudohdr {
    __u32 saddr;
    __u32 daddr;
    __u8 reserved;
    __u8 protocol;
    __u16 body_length;
}__attribute((packed));

#endif