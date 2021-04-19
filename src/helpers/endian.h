#ifndef __HELPER_ENDIAN_H__
#define __HELPER_ENDIAN_H__

#include <bpf/bpf_endian.h>
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

#endif