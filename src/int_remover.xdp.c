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
#define MAX_COPY_REMAINDER (sizeof(struct iphdr) + sizeof(struct tcphdr) + MAX_IPOPTLEN*2)

/**
 * Remove the INT shim, header and 
 */
SEC("xdp_remove_int")
int remove_int(struct xdp_md *ctx)
{
    struct hdr_cursor cursor = 
    {
        .start = (void*)(long)ctx->data,
        .pos = (void*)(long)ctx->data,
        .end = (void*)(long)ctx->data_end,
    };
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct int14_shim_t *int_shim;
    
    __u16 temp16 = ntohs(parse_ethhdr(&cursor, &eth));
    switch(temp16)
    {
        case ETH_P_IP:
            break;
        default:
            goto PASS;
    }

    __u8 temp8 = parse_iphdr(&cursor, &ip);

    switch(temp8)
    {
        case 6: // TCP
            goto PASS;
            if(parse_tcphdr(&cursor, &tcp))
                goto PASS;
            break;
        case 17: // UPD
            if (parse_udphdr(&cursor, &udp))
                goto PASS;
            break;
        default:
            goto PASS;
    }

    //Read DSCP from ip header
    __u8 dscp = ip->tos >> 2;
    if ((dscp & DSCP_INT) ^ DSCP_INT) // Return true if bits are not set.
        goto PASS;

    if (parse_inthdr(&cursor, &int_shim))
        goto PASS;

    __u16 int_totcsum = int_checksum(int_shim, cursor.end); //Using cursor.pos really should have worked, but didnt

    size_t int_length = int_shim->len;
    int_length = int_length << 2;

    void * source_cursor = ((void *)int_shim);
    void * dest_cursor = cursor.pos;

    if (source_cursor > cursor.end || dest_cursor > cursor.end)
        goto PASS;

    if (source_cursor - MIN_COPY < cursor.start || dest_cursor - MIN_COPY < cursor.start)
        goto PASS;

    // Begin modifying

    update_udphdr_check(udp, ~int_totcsum);

    __s16 length_delta = -int_length;
    // In order to complete this
    update_iphdr_length(ip, length_delta);
    udpate_iphdr_tos(ip, ((__u8*)int_shim)[3]);
    udpate_udphdr_length(udp, length_delta);

    int copy_size;

    // Copy min required

    copy_size = sizeof(struct ethhdr);
    source_cursor -= copy_size;
    dest_cursor -= copy_size;

    memmove(dest_cursor, source_cursor, copy_size); // Most problematic part complete

    //copy_size = sizeof(struct iphdr);
    //source_cursor -= copy_size;
    //dest_cursor -= copy_size;

    //memmove(dest_cursor, source_cursor, copy_size);//Point of failure

    // copy_size = sizeof(struct udphdr);
    // source_cursor -= copy_size;
    // dest_cursor -= copy_size;

    // memmove(dest_cursor, source_cursor, copy_size);

    copy_size = source_cursor - cursor.start;

    #pragma unroll
    for (int i = 0; i < MAX_COPY_REMAINDER / 4; i++)
    {
        if (i >= copy_size || source_cursor < cursor.start)
        {
            break;
        }
        else
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