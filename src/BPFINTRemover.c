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
#include "common_helpers.h"
#include "eth_helpers.h"
#include "ip_helpers.h"
#include "tcp_helpers.h"
#include "udp_helpers.h"
#include "int_helpers.h"

/**
 * Remove the INT shim, header and 
 */
SEC("remove_int")
int remove_int(struct xdp_md *ctx)
{
    struct hdr_cursor cursor = 
    {
        .pos = (void*)(long)ctx->data,
    };
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct int14_shim_t *int_shim;
    
    __u16 temp16 = ntohs(parse_ethhdr(&cursor, data_end, &eth));
    switch(temp16)
    {
        case ETH_P_IP:
            break;
        default:
            printf("Wrong protocol number: %d\n", temp16);
            goto PASS;
    }

    __u8 temp8 = parse_iphdr(&cursor, data_end, &ip);

    switch(temp8)
    {
        case 6: // TCP
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

    parse_int(&cursor, data_end, &int_shim);
    print_inthdr(int_shim);

    print_xdp_md(ctx);

    __u16 old_body_len = ntohs(ip->tot_len) - (((__u16)ip->ihl) << 2);
    __s16 length_delta = -(((__u16)int_shim->len) << 2);
    update_iphdr_length(ip, length_delta);
    update_udphdr_check(udp, length_delta);
    update_udphdr_check(udp, -int_checksum(int_shim));

    // TODO: Replace memmove with unrollable loop
    memmove(ctx->data - length_delta, ctx->data, (void*)int_shim - ctx->data);

    // Operation completed
    bpf_xdp_adjust_head(ctx, length_delta);
    
PASS:
    return XDP_PASS;
}