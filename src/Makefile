
# Set targets

APP = int_remover

# Universal Dependencies

OUTPUT_DIR := $(abspath ../output/)

INCLUDE_DIR := $(OUTPUT_DIR)

LIBBPF_DIR := $(abspath ../libbpf/src/)

OBJECT_LIBBPF := $(abspath $(OUTPUT_DIR)/libbpf.a)

UNIVERSAL_INCLUDES += -I$(OUTPUT_DIR)

# Filter Dependencies

FILTER_OBJ_CFLAGS +=

FILTER_ASM_CFLAGS += $(UNIVERSAL_INCLUDES)

FILTER_ASM_CFLAGS += -Wall
FILTER_ASM_CFLAGS += -Wno-unused-value
FILTER_ASM_CFLAGS += -Wno-pointer-sign
FILTER_ASM_CFLAGS += -Wno-compare-distinct-pointer-types
FILTER_ASM_CFLAGS += -Werror
FILTER_ASM_CFLAGS += -O2
FILTER_ASM_CFLAGS += -g
FILTER_ASM_CFLAGS += -S
FILTER_ASM_CFLAGS += -c

# Define loader dependencies

LOADER_CFLAGS += $(UNIVERSAL_INCLUDES)

LIB_LINKS += -L$(OUTPUT_DIR)
LIB_LINKS += -l:libbpf.a
LIB_LINKS += -lelf
LIB_LINKS += -lz

LOADER_CFLAGS += $(LIB_LINKS)

.PHONY: clean

.DELETE_ON_ERROR:

.SECONDARY:

all: $(APP)

$(APP): %: %.c $(OUTPUT_DIR)/%.skel.h $(OBJECT_LIBBPF) | $(OUTPUT_DIR)
	gcc -o $@ $< $(LOADER_CFLAGS)

$(OUTPUT_DIR)/%.skel.h: $(OUTPUT_DIR)/%.xdp.o | $(OUTPUT_DIR)
	bpftool gen skeleton $< > $@

$(OUTPUT_DIR)/%.xdp.o: $(OUTPUT_DIR)/%.xdp.ll | $(OUTPUT_DIR)
	llc $(FILTER_OBJ_CFLAGS) -march=bpf -filetype=obj -o $@ $<

$(OUTPUT_DIR)/%.xdp.ll: %.xdp.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h $(wildcard **/*.h) | $(OUTPUT_DIR)
	clang -target bpf $(FILTER_ASM_CFLAGS) -emit-llvm -o $@ $<

$(OUTPUT_DIR)/vmlinux.h: /sys/kernel/btf/vmlinux | $(OUTPUT_DIR)
	bpftool btf dump file $< format c > $@

$(OUTPUT_DIR):
	mkdir -p $@

$(OBJECT_LIBBPF):
	$(MAKE) -C $(LIBBPF_DIR) BUILD_STATIC_ONLY=1 \
	OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)    \
	INCLUDEDIR= LIBDIR= UAPIDIR=                \
	install

test: test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c $(INCLUDE_HEADERS)
	gcc -o $@ -D __DEBUG__ test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c

clean:
	rm -rf $(OUTPUT_DIR)
	rm $(APP)