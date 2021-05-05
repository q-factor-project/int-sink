
# Set targets

APP = int_remover

# Universal Dependencies

OUTPUT_DIR := $(abspath ../output/)

SRC_DIR := $(abspath ./)

LIBBPF_DIR := $(abspath ../libbpf/src/)

OBJECT_LIBBPF := $(abspath $(OUTPUT_DIR)/libbpf.a)

UNIVERSAL_INCLUDES += -I$(OUTPUT_DIR) -I$(SRC_DIR)

export OUTPUT_DIR SRC_DIR LIBBPF_DIR OBJECT_LIBBPF UNIVERSAL_INCLUDES

# Genral C Compilation

CC = clang

AR = llvm-ar

CFLAGS += $(UNIVERSAL_INCLUDES)

LDFLAGS += -L$(OUTPUT_DIR)
LDLIBS += -l:libbpf.a
LDLIBS += -lelf
LDLIBS += -lz

export CC AR CFLAGS LDFLAGS LDLIBS

# BPF compilation

BPFCFLAGS += $(UNIVERSAL_INCLUDES)
BPFCFLAGS += -Wall
BPFCFLAGS += -Wno-unused-value
BPFCFLAGS += -Wno-pointer-sign
BPFCFLAGS += -Wno-compare-distinct-pointer-types
BPFCFLAGS += -Werror
BPFCFLAGS += -O2
BPFCFLAGS += -g
BPFCFLAGS += -c

BPF_ARCH := -target bpf

COMPILE.bpf.c = $(CC) $(BPFCFLAGS) $(BPF_ARCH)

export COMPILE.bpf.c BPFCFLAGS BPF_ARCH

# Define loader dependencies

LOADER_CFLAGS += $(UNIVERSAL_INCLUDES)

LIB_LINKS += -L$(OUTPUT_DIR)
LIB_LINKS += -l:libbpf.a
LIB_LINKS += -lelf
LIB_LINKS += -lz

LOADER_CFLAGS += $(LIB_LINKS)

.DELETE_ON_ERROR:

.SECONDARY:

all: $(APP)

####################
# Explicit Targets #
####################

$(APP): %: %.c $(OUTPUT_DIR)/%.skel.h $(OBJECT_LIBBPF) | $(OUTPUT_DIR)
	gcc -o $@ $< $(LOADER_CFLAGS)

int_remover2.bpf.o: xdp/int_remover.bpf.o helpers/bpf.a
	$(CC) $(OUTPUT_OPTION) $^

test: test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c $(INCLUDE_HEADERS)
	gcc -o $@ -D __DEBUG__ test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c

#################
# Build Objects #
#################

%.skel.h: %.bpf.o 
	bpftool gen skeleton $< > $@

%.bpf.o: %.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h FORCE
	$(MAKE) -C $(dir $@) $(notdir $@) 

%.bpf.ll: %.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h FORCE
	$(MAKE) -C $(dir $@) $(notdir $@)

%.a: $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h FORCE
	$(MAKE) -C $(dir $@) $(notdir $@)

#################
# Build library #
#################

$(OBJECT_LIBBPF):
	$(MAKE) -C $(LIBBPF_DIR) BUILD_STATIC_ONLY=1 \
	OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)    \
	INCLUDEDIR= LIBDIR= UAPIDIR=                \
	install

$(OUTPUT_DIR)/vmlinux.h: /sys/kernel/btf/vmlinux | $(OUTPUT_DIR)
	bpftool btf dump file $< format c > $@

$(OUTPUT_DIR):
	mkdir -p $@

##################
# Cleaning rules #
##################

SUBDIRS := helpers xdp

phony += $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

phony += clean

clean: $(SUBDIRS)
	-rm -rf $(OUTPUT_DIR)
	-rm -f $(APP)
	-rm -f *.skel.h
	-rm -f int_remover2.bpf.o

phony += FORCE

FORCE:

.PHONY: $(phony)