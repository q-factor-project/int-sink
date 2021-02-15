/* 
 * Remove INT information
 * Remove INT Header
 * Rewrite References to Packet Length
 * Recalculate Appropriate Checksums
 * 
 * Steps:
 * 1. Calculate area to be removed.
 * 2. Mo
 */


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "helpers/common.h"
#include "helpers/ethernet.h"
#include "helpers/ip.h"
#include "helpers/tcp.h"
#include "helpers/udp.h"
#include "helpers/int.h"

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#define MIN_COPY (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define MAX_COPY_REMAINDER (sizeof(struct tcphdr) - sizeof(struct udphdr) + MAX_IPOPTLEN*2)

/**
 * Remove the INT shim, header and 
 */
SEC("xdp_remove_int")
int remove_int(struct xdp_md *ctx)
{
    struct hdr_cursor cursor = 
    {
        .pos = (void*)(long)ctx->data,
    };
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct int14_shim_t *int_shim;
    
    __u16 temp16 = ntohs(parse_ethhdr(&cursor, data_end, &eth));
    switch(temp16)
    {
        case ETH_P_IP:
            break;
        default:
            goto PASS;
    }

    __u8 temp8 = parse_iphdr(&cursor, data_end, &ip);

    switch(temp8)
    {
        case 6: // TCP
            goto PASS;
            if(parse_tcphdr(&cursor, data_end, &tcp))
                goto PASS;
            break;
        case 17: // UPD
            if (parse_udphdr(&cursor, data_end, &udp))
                goto PASS;
            break;
        default:
            goto PASS;
    }

    //Read DSCP from ip header
    __u8 dscp = ip->tos >> 2;
    if ((dscp & DSCP_INT) ^ DSCP_INT) // Return true if bits are not set.
        goto PASS;

    // Good up until here
    parse_int(&cursor, data_end, &int_shim);

    __s16 length_delta = -(((__u16)int_shim->len) << 2);

    update_iphdr_length(ip, length_delta);
    udpate_iphdr_tos(ip, ((__u8*)int_shim)[3]);
    udpate_udphdr_length(udp, length_delta);
    if (((void *)int_shim) + int_shim->len > data_end)
        goto PASS;
    __u16 int_totcsum = int_checksum(int_shim);
    update_udphdr_check(udp, ~int_totcsum);
    

    // TODO: Replace memmove with constant size operation
    // memmove((void *)ctx->data - length_delta, (void*)ctx->data, (__u64)int_shim - ctx->data);

    int copy_size;
    void * source_cursor = ((void *)int_shim);
    void * dest_cursor = ((void *)int_shim) - length_delta;

    if (dest_cursor > data_end)
        goto PASS;

    // Copy min required

    copy_size = MIN_COPY;
    source_cursor -= copy_size;
    dest_cursor -= copy_size;
    memmove(dest_cursor, source_cursor, copy_size);

    // Copy remainder
    // max remainder = (sizeof(struct tcphdr) - sizeof(struct udphdr) + MAX_IPOPTLEN*2)

    copy_size = ((__u64)int_shim - (__u64)data_end) - copy_size;

    #pragma unroll
    for (int i = 0; i < MAX_COPY_REMAINDER / 4; i++)
    {
        if (i < copy_size)
        {
            source_cursor-= 4, dest_cursor -= 4;
            *((__u32 *)dest_cursor) = *((__u32 *)source_cursor);
        }
    }


    // Operation completed
    bpf_xdp_adjust_head(ctx, length_delta);
    
PASS:
    return XDP_PASS;
}