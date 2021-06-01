# INT Remover Targets

obj-bpf-int-remove := int_pop.bpf.o 

target-int-remove-skel := int_remover.skel.h

# INT Inserter Targets

obj-bpf-int-insert := int_push.bpf.o

target-int-insert-skel := int_inserter.skel.h

# Generic Targets

obj-bpf-generic := driver.bpf.o tcp.bpf.o udp.bpf.o ip.bpf.o ethernet.bpf.o

obj-bpf := $(obj-bpf-int-insert) $(obj-bpf-int-remove) $(obj-bpf-generic)

target-skel := $(target-int-insert-skel) $(target-int-remove-skel)

# Rules

phony += all

all: $(target-skel)

dep-bpf := $(obj-bpf:.bpf.o=.bpf.d)

$(dep-bpf): %.bpf.d: %.c
	$(COMPILE.test.c) $< -M -MT '$(@:.d=.o) $@' > $@

-include $(dep-bpf)

target-bpf := $(target-skel:.skel.h=.bpf.o)

$(target-int-remove-skel:.skel.h=.bpf.o): $(obj-bpf-int-remove) $(obj-bpf-generic)

$(target-int-insert-skel:.skel.h=.bpf.o): $(obj-bpf-int-insert) $(obj-bpf-generic)

$(target-skel): %.skel.h: %.bpf.o
	$(BPFTOOL) gen skel $< > $@

$(target-bpf):
	$(BPFTOOL) gen object $@ $^

$(obj-bpf): %.bpf.o: %.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h
	$(COMPILE.bpf.c) $(OUTPUT_OPTION) $<

phony += clean

clean-targets += $(target-skel) $(target-bpf) $(obj-bpf) $(dep-bpf)

clean:
	-rm -f $(clean-targets)

.PHONY: $(phony)

.DELETE_ON_ERROR:

.SECONDARY:

test: all

# include $(SRC_DIR)/scripts/Makefile.test.build