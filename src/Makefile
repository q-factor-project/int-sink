
TARGET_FILTER := int_remover

TARGET_LOADER := xdp_loader

INCLUDE_DIR ?= ../headers/

FILTER_C = ${TARGET_FILTER:=.xdp.c}

FILTER_LLVM_ASM = ${FILTER_C:.xdp.c=.xdp.ll}

FILTER_ASM = ${FILTER_LLVM_ASM:.xdp.ll=.xdp.s}

FILTER_OBJ = ${FILTER_LLVM_ASM:.xdp.ll=.xdp.o}

LOADER_C = ${TARGET_LOADER:=.c}

INCLUDE_HEADERS := $(wildcard $(INCLUDE_DIR)**/*.h)

LIBBPF_DIR ?= ../libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

LIBS = -L$(LIBBPF_DIR) -l:libbpf.a -lelf -lz

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I$(INCLUDE_DIR)

.PHONY: clean

all: $(FILTER_OBJ) $(TARGET_LOADER)

.PHONY: clean

test: test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c $(INCLUDE_HEADERS)
	gcc -o $@ -D __DEBUG__ -I$(INCLUDE_DIR) test.c int_remover.xdp.c ./debug/print.c ./mock/bpf.c

$(TARGET_LOADER): %: %.c $(OBJECT_LIBBPF) $(INCLUDE_HEADERS)
	gcc -o $@ $< -I$(INCLUDE_DIR) $(CFLAGS) $(LIBS)

$(FILTER_LLVM_ASM): %.xdp.ll: %.xdp.c $(OBJECT_LIBBPF) $(INCLUDE_HEADERS)
	clang -S \
	    -target bpf \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<

$(FILTER_ASM): %.xdp.s: %.xdp.ll
	llc -march=bpf -filetype=asm -o $@ $<

$(FILTER_OBJ): %.xdp.o: %.xdp.ll
	llc -march=bpf -filetype=obj -o $@ $<

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -f $(FILTER_LLVM_ASM)
	rm -f $(FILTER_OBJ)
	rm -f $(FILTER_ASM)
	rm -f $(TARGET_LOADER)
	rm -f test