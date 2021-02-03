#pragma once

#include <stdio.h>
#include "common_helpers.h"
#include "eth_helpers.h"
#include "ip_helpers.h"
#include "tcp_helpers.h"
#include "udp_helpers.h"
#include "int_helpers.h"
#include <string.h>

struct xdp_md {
    void* data;
    void* data_end;
};

long bpf_xdp_adjust_head(struct xdp_md *ctx, int length)
{
    ctx->data -= length;
    return 0;
}

// Based on code similar to that in the kernel
__s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed)
{
    __u64 diff_size = from_size + to_size;
    int i = 0, j = 0;
    __u64 sum = seed;
    for (i = 0; i < from_size / sizeof(__be32); i++)
    {
        sum += ~from[i];
    }
    for (i = 0; i < to_size / sizeof(__be32); i++)
    {
        sum += to[i];
    }
    
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); // Fold into 32 bits
    sum = (sum >> 32) + (sum & 0xFFFFFFFF); 
    sum = (sum >> 16) + (sum & 0xFFFF); // Fold into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    return sum;
}

#define PRINT_BYTES(_ptr, _start, _end) \
{\
    for(_ptr = (void*)(_start); (void*)(_ptr) < (void*)(_end); _ptr++)\
    {\
        printf("%02hx", *ptr);\
    }\
}\

#define PRINT_MEMBER_BYTES(_ptr, _target, _struct, _member)\
PRINT_BYTES(_ptr, ((void*)_target) + offsetof(_struct, _member), ((void*)_target) + offsetof(_struct, _member) + sizeof(_target->_member))

int print_xdp_md(struct xdp_md *ctx)
{
    __u8* ptr;
    printf("Raw packet\n\t");
    PRINT_BYTES(ptr, ctx->data, ctx->data_end);
    printf("\n");
    return 0;
}

int print_ethhdr(struct ethhdr *ethhdr)
{
    __u8* ptr;
    printf("Ethernet Header\n\tBytes: ");
    PRINT_BYTES(ptr, ethhdr, ((void*)ethhdr) + sizeof(struct ethhdr))
    printf("\n\tDestination: ");
    PRINT_MEMBER_BYTES(ptr, ethhdr, struct ethhdr, h_dest)
    printf("\n\tSource: ");
    PRINT_MEMBER_BYTES(ptr, ethhdr, struct ethhdr, h_source)
    printf("\n\tProtocol (HEXADECIMAL): ");
    PRINT_MEMBER_BYTES(ptr, ethhdr, struct ethhdr, h_proto)
    printf("\n\tProtocol (Decimal): %d", ntohs(ethhdr->h_proto));
    printf("\n");
    return 0;
}



int print_ippseudohdr(struct ippseudohdr *ippseudohdr)
{
    __u8* ptr;
    printf("IP Pseudo Header\n\tBytes: ");
    PRINT_BYTES(ptr, ippseudohdr, ((void*)ippseudohdr) + sizeof(struct ippseudohdr))
    printf("\n\tBody length: %d", ippseudohdr->body_length);
    int sum = bpf_csum_diff(0, 0, (void *)ippseudohdr, sizeof(struct ippseudohdr), 0);
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n");
}

int print_iphdr(struct iphdr *iphdr)
{
    __u8* ptr;
    printf("IPv4 Header\n\tBytes: ");
    PRINT_BYTES(ptr, iphdr, ((void*)iphdr) + iphdr->ihl * 4)
    printf("\n\tDestination: ");
    PRINT_MEMBER_BYTES(ptr, iphdr, struct iphdr, daddr)
    printf("\n\tSource: ");
    PRINT_MEMBER_BYTES(ptr, iphdr, struct iphdr, saddr)
    printf("\n\tTOS: ");
    PRINT_MEMBER_BYTES(ptr, iphdr, struct iphdr, tos)
    printf("\n\tIHL(DECIMAL): %d", iphdr->ihl);
    printf("\n\tTotal Length (HEXADECIMAL): ");
    PRINT_MEMBER_BYTES(ptr, iphdr, struct iphdr, tot_len)
    printf("\n\tTotal Length (DECIMAL): %d", ntohs(iphdr->tot_len));
    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(ptr, iphdr, struct iphdr, check)
    int sum = bpf_csum_diff(0, 0, (void *)iphdr, iphdr->ihl * 4, 0);
    printf("\n\tChecksum Total: %04hx", sum);
    printf("\n");
    
    return 0;
}

int print_udphdr(struct udphdr *udphdr, int body_length)
{
    __u8* ptr;
    printf("UDP Header\n\tBytes: ");
    PRINT_BYTES(ptr, udphdr, ((void*)udphdr) + sizeof(struct udphdr))
    int sum = bpf_csum_diff(0, 0, (void *)udphdr, body_length, 0);
    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(ptr, udphdr, struct udphdr, check)
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n\tBody Bytes: ");
    PRINT_BYTES(ptr, ((void*)udphdr) + sizeof(struct udphdr), ((void*)udphdr) + body_length)
    printf("\n");
    return 0;
}

int print_tcphdr(struct tcphdr *tcphdr, int body_length)
{
    __u8* ptr;
    printf("TCP Header\n\tBytes: ");
    PRINT_BYTES(ptr, tcphdr, ((void*)tcphdr) + tcphdr->doff * 4)
    printf("\n\tData offset(DECIMAL): %d", tcphdr->doff);
    int sum = bpf_csum_diff(0, 0, (void *)tcphdr, body_length, 0);
    printf("\n\tChecksum: ");
    PRINT_MEMBER_BYTES(ptr, tcphdr, struct tcphdr, check)
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n\tBody Bytes: ");
    PRINT_BYTES(ptr, ((void*)tcphdr) + tcphdr->doff * 4, ((void*)tcphdr) + body_length)
    printf("\n");
    return 0;
}

int print_inthdr(struct int14_shim_t *inthdr)
{
    __u8* ptr;
    printf("INT Header\n\tBytes: ");
    PRINT_BYTES(ptr, inthdr, ((void*)inthdr) + inthdr->len * 4)
    printf("\n\tLength(DECIMAL): %d", inthdr->len);
    int sum = bpf_csum_diff(0, 0, (void *)inthdr, inthdr->len * 4, 0);
    printf("\n\tPartial Checksum: %04hx", sum);
    printf("\n");
    return 0;
}

