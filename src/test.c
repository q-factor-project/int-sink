#include "helpers/debug.h"
#include "helpers/common.h"
#include "helpers/ethernet.h"
#include "helpers/ip.h"
#include "helpers/tcp.h"
#include "helpers/udp.h"
#include "helpers/int.h"

#define MAX_COPY_REMAINDER (sizeof(struct tcphdr) - sizeof(struct udphdr) + MAX_IPOPTLEN*2)


//Tool for experimenting with the packet parsing
int main(int argc, char** argv)
{
    char packet[] = "\x00\x15\x5d\x00\x68\x18\x00\x15\x5d\x00\x68\x03\x08\x00\x45\x5c\x00\x34\x00\x01\x00\x00\x40\x11\xf9\x06\xc0\xa8\x00\x02\xc0\xa8\x00\x03\x17\x0c\x17\x0c\x00\x20\xf5\x37\x01\x00\x03\x28\x10\x00\x06\x0a\xfc\x00\x00\x00\x00\x00\x00\x01\x16\x60\x4e\xdb\x49\xed\x95\xab";
    //char packet[] = "\x00\x15\x5d\x00\x68\x18\x00\x15\x5d\x00\x68\x03\x08\x00\x45\x5c\x00\x34\x00\x01\x00\x00\x40\x11\xf9\x06\xc0\xa8\x00\x02\xc0\xa8\x00\x03\x17\x0c\x17\x0c\x00\x20\x96\xa3\x01\x00\x03\x28\x10\x00\x06\x0a\xfc\x00\x00\x00\x00\x00\x00\xf9\x16\x5f\xfa\xda\x5a\xdd\x36\x59";
    struct xdp_md xdp_frame = {
        .data = packet,
        .data_end = packet + sizeof(packet) - 1, // subtract 1 to exclude null terminator
    };
    struct xdp_md *ctx = &xdp_frame;

    print_xdp_md(ctx);

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
    print_ethhdr(eth);
    switch(temp16)
    {
        case ETH_P_IP:
            break;
        default:
            goto PASS;
    }

    __u8 temp8 = parse_iphdr(&cursor, data_end, &ip);
    print_iphdr(ip);
    struct ippseudohdr ippseudohdr = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .reserved = 0,
        .protocol = ip->protocol,
        .body_length = htons(ntohs(ip->tot_len) - (((__u16)ip->ihl) << 2)),
    };
    print_ippseudohdr(&ippseudohdr);

    switch(temp8)
    {
        case 6: // TCP
            if(parse_tcphdr(&cursor, data_end, &tcp))
                goto PASS;
            print_tcphdr(tcp, ippseudohdr.body_length);
            break;
        case 17: // UPD
            if (parse_udphdr(&cursor, data_end, &udp))
                goto PASS;
            print_udphdr(udp);
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

    printf("Unmodified ");
    print_xdp_md(ctx);

    __s16 length_delta = -(((__u16)int_shim->len) << 2);

    update_iphdr_length(ip, length_delta);
    udpate_iphdr_tos(ip, ((__u8*)int_shim)[3]);
    udpate_udphdr_length(udp, length_delta);
    __u16 int_totcsum = int_checksum(int_shim);
    printf("Removed segment partial checksum: %d\n", int_totcsum);
    update_udphdr_check(udp, ~int_totcsum);

    printf("Modified ");
    print_xdp_md(ctx);

    // TODO: Replace memmove with constant size operation
    // memmove((void *)ctx->data - length_delta, (void*)ctx->data, (__u64)int_shim - ctx->data);

    int copy_size;
    void * source_cursor = ((void *)int_shim);
    void * dest_cursor = ((void *)int_shim) - length_delta;

    // Copy min required
    copy_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    source_cursor -= copy_size;
    dest_cursor -= copy_size;
    memmove(dest_cursor, source_cursor, copy_size);

    printf("Shrink 1 ");
    print_xdp_md(ctx);

    // max remainder = (sizeof(struct tcphdr) - sizeof(struct udphdr) + MAX_IPOPTLEN*2)
    // Copy remainder

    printf("Copy size %d\n", copy_size);
    copy_size = ((__u64)int_shim - (__u64)ctx->data) - copy_size;
    printf("Copy size %d\n", copy_size);

    for(int i = 0; i < MAX_COPY_REMAINDER; i++)
    {
        if (i >= copy_size)
        {
            break;
        }
        source_cursor--, dest_cursor--;
        *((char *)dest_cursor) = *((char *)source_cursor);
    }

    printf("Shrink 2 ");
    print_xdp_md(ctx);

    // Operation completed
    bpf_xdp_adjust_head(ctx, length_delta);

    print_xdp_md(ctx);

    //Done

    //Verify results

    data_end = (void*)(long)ctx->data_end;
    cursor.pos = ctx->data;

    print_xdp_md(ctx);

    temp16 = ntohs(parse_ethhdr(&cursor, data_end, &eth));
    print_ethhdr(eth);
    switch(temp16)
    {
        case ETH_P_IP:
            break;
        default:
            printf("Wrong protocol number: %d\n", temp16);
            goto PASS;
    }

    temp8 = parse_iphdr(&cursor, data_end, &ip);
    print_iphdr(ip);

    ippseudohdr.saddr = ip->saddr;
    ippseudohdr.daddr = ip->daddr;
    ippseudohdr.reserved = 0;
    ippseudohdr.protocol = ip->protocol;
    ippseudohdr.body_length = htons(ntohs(ip->tot_len) - (((__u16)ip->ihl) << 2));
    print_ippseudohdr(&ippseudohdr);

    switch(temp8)
    {
        case 6: // TCP
            if(parse_tcphdr(&cursor, data_end, &tcp))
                goto PASS;
            print_tcphdr(tcp, ippseudohdr.body_length);
            break;
        case 17: // UPD
            if (parse_udphdr(&cursor, data_end, &udp))
                goto PASS;
            print_udphdr(udp);
            break;
        default:
            goto PASS;
    }


    return 0;
PASS:
    return -1;
}