#include <linux/types.h>


struct redirect_info
{
    __u8 dest[6];
    __u8 src[6];
    __u32 ifindex;
};