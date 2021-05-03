#include "int_remover.xdp.h"
#include "debug/print.h"

int parse_packet(struct xdp_md *xdp_frame)
{
    print_xdp_md(&xdp_frame);
    
    void* cursor;
    void* data_end;

    cursor = xdp_frame->data;
    data_end = xdp_frame->data_end;

    struct ethhdr *eth = cursor;

    if(eth + 1 > data_end)
        return -1;

    print_ethhdr(eth);

    cursor += sizeof(struct ethhdr);

    struct iphdr *ip = cursor;

    if(ip + 1 > data_end)
        return -1;

    print_iphdr(ip);

    cursor += sizeof(struct iphdr);

    struct ippseudohdr pseudo = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .reserved = 0,
        .protocol = ip->protocol,
        .body_length = htons(ntohs(ip->tot_len) - (ip->ihl << 2)),
    };

    print_ippseudohdr(&pseudo);

    struct udphdr *udp = cursor;

    if(udp + 1 > data_end)
        return -1;

    print_udphdr(udp);



    return 0;
}




int main(int argc, char** argv)
{
    char packet[] = "\x00\x15\x5d\x00\x68\x18\x00\x15\x5d\x00\x68\x03\x08\x00\x45\x5c\x00\x34\x00\x01\x00\x00\x40\x11\xf9\x06\xc0\xa8\x00\x02\xc0\xa8\x00\x03\x17\x0c\x17\x0c\x00\x20\xf5\x37\x01\x00\x03\x28\x10\x00\x06\x0a\xfc\x00\x00\x00\x00\x00\x00\x01\x16\x60\x4e\xdb\x49\xed\x95\xab";

    struct xdp_md xdp_frame = {
        .data = packet,
        .data_end = packet + sizeof(packet) - 1, // subtract 1 to exclude null terminator
    };

    parse_packet(&xdp_frame);

    remove_int(&xdp_frame);

    parse_packet(&xdp_frame);
}