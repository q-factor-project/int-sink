
#include "print.h"
#include <stdio.h>
#include <string.h>
#include "../mock/bpf.h"

#define PRINT_BYTES(_start, _end) \
{\
    __u8* ptr;\
    for(ptr = (void*)(_start); (void*)(ptr) < (void*)(_end); ptr++)\
    {\
        printf("%02hx", *ptr);\
    }\
}\

#define PRINT_MEMBER_BYTES(_target, _struct, _member)\
PRINT_BYTES(((void*)_target) + offsetof(_struct, _member), ((void*)_target) + offsetof(_struct, _member) + sizeof(_target->_member))

int print_xdp_md(struct xdp_md *ctx)
{
    printf("Raw packet\n\t");
    PRINT_BYTES(ctx->data, ctx->data_end);
    printf("\n");
    return 0;
}

int print_ethhdr(struct ethhdr *ethhdr)
{
    printf("Ethernet Header\n\tBytes: ");
    PRINT_BYTES(ethhdr, ((void*)ethhdr) + sizeof(struct ethhdr))
    printf("\n\tDestination: ");
    PRINT_MEMBER_BYTES(ethhdr, struct ethhdr, h_dest)
    printf("\n\tSource: ");
    PRINT_MEMBER_BYTES(ethhdr, struct ethhdr, h_source)
    printf("\n\tProtocol (HEXADECIMAL): ");
    PRINT_MEMBER_BYTES(ethhdr, struct ethhdr, h_proto)
    printf("\n\tProtocol (Decimal): %d", ntohs(ethhdr->h_proto));
    printf("\n");
    return 0;
}



int print_ippseudohdr(struct ippseudohdr *ippseudohdr)
{
    printf("IP Pseudo Header\n\tBytes: ");
    PRINT_BYTES(ippseudohdr, ((void*)ippseudohdr) + sizeof(struct ippseudohdr))
    printf("\n\tBody length: %d", ntohs(ippseudohdr->body_length));
    int sum = bpf_csum_diff(0, 0, (void *)ippseudohdr, sizeof(struct ippseudohdr), 0);
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n");
}

int print_iphdr(struct iphdr *iphdr)
{
    printf("IPv4 Header\n\tBytes: ");
    PRINT_BYTES(iphdr, ((void*)iphdr) + iphdr->ihl * 4)
    printf("\n\tDestination: ");
    PRINT_MEMBER_BYTES(iphdr, struct iphdr, daddr)
    printf("\n\tSource: ");
    PRINT_MEMBER_BYTES(iphdr, struct iphdr, saddr)
    printf("\n\tTOS: ");
    PRINT_MEMBER_BYTES(iphdr, struct iphdr, tos)
    printf("\n\tIHL(DECIMAL): %d", iphdr->ihl);
    printf("\n\tTotal Length (HEXADECIMAL): ");
    PRINT_MEMBER_BYTES(iphdr, struct iphdr, tot_len)
    printf("\n\tTotal Length (DECIMAL): %d", ntohs(iphdr->tot_len));
    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(iphdr, struct iphdr, check)
    int sum = bpf_csum_diff(0, 0, (void *)iphdr, iphdr->ihl * 4, 0);
    printf("\n\tChecksum Total: %04hx", sum);
    printf("\n");
    
    return 0;
}

int print_udphdr(struct udphdr *udphdr)
{
    printf("UDP Header\n\tBytes: ");
    PRINT_BYTES(udphdr, ((void*)udphdr) + sizeof(struct udphdr))
    int body_length = ntohs(udphdr->len);
    printf("\n\tLength: %d", body_length);

    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(udphdr, struct udphdr, check)
    int sum = bpf_csum_diff(0, 0, (void *)udphdr, body_length, 0);
    printf("\n\tPartial Checksum(Header + Body): %04hx", sum);
    sum = bpf_csum_diff(0, 0, (void *)udphdr, sizeof(struct udphdr), 0);
    printf("\n\tPartial Checksum(Header): %04hx", sum);
    sum = bpf_csum_diff(0, 0, (void *)udphdr + sizeof(struct udphdr), body_length - sizeof(struct udphdr), 0);
    printf("\n\tPartial Checksum(Body): %04hx", sum);
    printf("\n\tBody Bytes: ");
    PRINT_BYTES(((void*)udphdr) + sizeof(struct udphdr), ((void*)udphdr) + body_length)
    printf("\n");
    return 0;
}

int print_tcphdr(struct tcphdr *tcphdr, int body_length)
{
    printf("TCP Header\n\tBytes: ");
    PRINT_BYTES(tcphdr, ((void*)tcphdr) + tcphdr->doff * 4)
    printf("\n\tData offset(DECIMAL): %d", tcphdr->doff);
    int sum = bpf_csum_diff(0, 0, (void *)tcphdr, body_length, 0);
    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(tcphdr, struct tcphdr, check)
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n\tBody Bytes: ");
    PRINT_BYTES(((void*)tcphdr) + tcphdr->doff * 4, ((void*)tcphdr) + body_length)
    printf("\n");
    return 0;
}

int print_inthdr(struct int14_shim_t *inthdr)
{
    printf("INT Header\n\tBytes: ");
    PRINT_BYTES(inthdr, ((void*)inthdr) + inthdr->len * 4)
    printf("\n\tLength(DECIMAL): %d", inthdr->len);
    int sum = bpf_csum_diff(0, 0, (void *)inthdr, inthdr->len * 4, 0);
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n");
    return 0;
}