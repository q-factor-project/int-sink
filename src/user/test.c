#include <xdp/int_remover.skel.h>
#include <bpf/bpf.h>
#include <unistd.h>

int run_test(int prog_fd, char *packet, unsigned int packet_size, unsigned int repetitions);

int main(int argc, char** argv)
{
    int err = 0;
    unsigned int duration = 0;
    unsigned int result;
    
    int prog_fd;
    struct int_remover_bpf *obj;

    obj = int_remover_bpf__open();

    if(!obj)
    {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        goto CLEANUP;
    }

    err = int_remover_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto CLEANUP;
    }

    // Get program file descriptor

    int map_fd = bpf_map__fd(obj->maps.int_buffer);
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to retrieve map file descriptor.\n");
        goto CLEANUP;
    }

    prog_fd = bpf_program__fd(obj->progs.test_int);
    if (prog_fd < 0)
    {
        fprintf(stderr, "Failed to test_int program file descriptor.\n");
        goto CLEANUP;
    }
    char int_payload_packet[] = {0x01,0x00,0x03,0x28,0x10,0x00,0x06,0x0a,0xfc,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x16,0x60,0x4e,0xdb,0x49,0xed,0x95,0xab,0x00,0x00};
    fprintf(stdout, "Process int test run...\n");
    fprintf(stdout, "================================================================================\n");
    run_test(prog_fd, int_payload_packet, sizeof(int_payload_packet), 100);
    fprintf(stdout, "================================================================================\n");

    prog_fd = bpf_program__fd(obj->progs.remove_int);
    if (prog_fd < 0)
    {
        fprintf(stderr, "Failed to retrieve program file descriptor.\n");
        goto CLEANUP;
    }

    char full_udp_packet[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x08,0x00, // ETHERNET HEADER
                              0x45,0x5c,0x00,0x36,// IP HEADER
                              0x00,0x01,0x00,0x00,
                              0x40,0x11,0xf9,0x06,
                              0xc0,0xa8,0x00,0x02,
                              0xc0,0xa8,0x00,0x03,
                              0x17,0x0c,0x17,0x0c,// UDP HEADER
                              0x00,0x22,0xf5,0x33,
                              0x01,0x00,0x03,0x28,// INT Data
                              0x10,0x00,0x06,0x0a,
                              0xfc,0x00,0x00,0x00,
                              0x00,0x00,0x00,0x01,0x16,0x60,0x4e,0xdb,0x49,0xed,0x95,0xab,0x00,0x00};// Payload

    char full_tcp_packet[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x08,0x00,
                              0x45,0x5c,0x00,0x66,0x00,0x01,0x00,0x00,0x40,0x06,0xf9,0x06,0xc0,0xa8,0x00,0x02,0xc0,0xa8,0x00,0x03,0x17,0x0c,0x17,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x00,0x0a,0x00,0x9b,0x54,0x00,0x00,0x01,0x00,0x03,0x28,0x10,0x00,0x06,0x0a,0xfc,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x16,0x60,0x4e,0xdb,0x49,0xed,0x95,0xab,0x00,0x00};

    char short_full_packet[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xb, 0x0c, 0x08, 0x00, 0x45, 0x5c, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf9, 0x06, 0xc0, 0xa8, 0x00, 0x02, 0xc0, 0xa8, 0x00, 0x03, 0x17, 0x0c, 0x17, 0x0c, 0x00, 0x20, 0xf5, 0x37, 0x01, 0x00, 0x03, 0x28, 0x10, 0x00, 0x06, 0x0a, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x16, 0x60, 0x4e, 0xdb, 0x49, 0xed, 0x95, 0xab};
    
    fprintf(stdout, "Driver program test run for udp...\n");
    fprintf(stdout, "================================================================================\n");
    run_test(prog_fd, full_udp_packet, sizeof(full_udp_packet), 100);
    fprintf(stdout, "Packets processed: %d\n", obj->bss->counter);
    fprintf(stdout, "Packets dropped: %d\n", obj->bss->dropped);
    fprintf(stdout, "INT processed: %d\n", obj->bss->int_counter);
    fprintf(stdout, "================================================================================\n");
        fprintf(stdout, "Driver program test run for tcp...\n");
    fprintf(stdout, "================================================================================\n");
    run_test(prog_fd, full_tcp_packet, sizeof(full_tcp_packet), 100);
    fprintf(stdout, "Packets processed: %d\n", obj->bss->counter);
    fprintf(stdout, "Packets dropped: %d\n", obj->bss->dropped);
    fprintf(stdout, "INT processed: %d\n", obj->bss->int_counter);
    fprintf(stdout, "================================================================================\n");
CLEANUP:
    int_remover_bpf__destroy(obj);
    return 0;
}


int run_test(int prog_fd, char *packet, unsigned int packet_size, unsigned int repetitions)
{
    fprintf(stdout, "Packet IN size: %u\n", packet_size);
    fprintf(stdout, "Packet IN:\n");
    for (int i = 0; i < packet_size; i++) fprintf(stdout, "%02x ", (unsigned char)packet[i]);
    fprintf(stdout, "\n");

    char packet_out[1514];
    unsigned int packet_out_size;
    int ret_val;
    unsigned int duration;
    bpf_prog_test_run(prog_fd, repetitions, packet, packet_size, packet_out, &packet_out_size, &ret_val, &duration);
    fprintf(stdout, "Result: %d\n", ret_val);
    fprintf(stdout, "Duration: %u\n", duration);
    fprintf(stdout, "Packet OUT size: %u\n", packet_out_size);
    fprintf(stdout, "Packet OUT:\n");
    for (int i = 0; i < packet_out_size; i++) fprintf(stdout, "%02x ", (unsigned char)packet_out[i]);
    fprintf(stdout, "\n");
    return 0;
}