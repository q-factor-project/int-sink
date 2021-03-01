#pragma once

#ifdef __bpf__
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#else

#include "mock/bpf.h"

#endif

int remove_int(struct xdp_md *ctx);