
TARGET_FILTER := int_remover

FILTER_C = ${TARGET_FILTER:=.xdp.c}

FILTER_OBJ = ${FILTER_C:.xdp.c=.xdp.o}

INCLUDE_DIR ?= ../headers/

BPF_HELPER_HEADERS := $(wildcard $(INCLUDE_DIR)helpers/*.h) $(wildcard $(INCLUDE_DIR)types/*.h)

DEBUG_HEADERS := $(BPF_HELPER_HEADERS)

LIBBPF_DIR ?= ../libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I$(INCLUDE_DIR)

.PHONY: clean

all: $(FILTER_OBJ)

.PHONY: clean

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -f $(FILTER_OBJ) test

$(FILTER_OBJ): %.xdp.o: %.xdp.c $(BPF_HELPER_HEADERS) $(OBJECT_LIBBPF)
	clang -S \
	    -target bpf \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=asm -o ${@:.o=.s} ${@:.o=.ll}
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	

test: test.c $(DEBUG_HEADERS)
	gcc test.c -o $@ -D __DEBUG__ -I$(INCLUDE_DIR)

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi