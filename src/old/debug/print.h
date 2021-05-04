#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H

#include "../helpers/common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "../types/int.h"
#include "../types/ip_pseudo.h"
#include "../mock/types/xdp.h"

int print_xdp_md(struct xdp_md *ctx);

int print_ethhdr(struct ethhdr *ethhdr);

int print_ippseudohdr(struct ippseudohdr *ippseudohdr);

int print_iphdr(struct iphdr *iphdr);

int print_udphdr(struct udphdr *udphdr);

int print_tcphdr(struct tcphdr *tcphdr, int body_length);

int print_inthdr(struct int14_shim_t *inthdr);

#endif