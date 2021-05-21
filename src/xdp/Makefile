obj-bpf := driver.bpf.o int.bpf.o tcp.bpf.o udp.bpf.o ip.bpf.o ethernet.bpf.o

target-skel := int_remover.skel.h

include $(SRC_DIR)/scripts/Makefile.bpf.build

test: all

# include $(SRC_DIR)/scripts/Makefile.test.build