#pragma once

#ifdef __bpf__
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#else

#include "mock/bpf.h"

#endif

int remove_int(struct xdp_md *ctx);