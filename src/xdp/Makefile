# INT Remover Targets

obj-bpf-int-remove := int_pop.bpf.o 
obj-bpf-int-remove += tcp.bpf.o
obj-bpf-int-remove += udp.bpf.o
obj-bpf-int-remove += ip.bpf.o
obj-bpf-int-remove += ethernet.bpf.o
obj-bpf-int-remove += driver.bpf.o
obj-bpf-int-remove += entry.bpf.o

target-int-remove-skel := int_remover.skel.h

# XDP Test INT Removal Targets

obj-bpf-int-remove-test := $(obj-bpf-int-remove)
obj-bpf-int-remove-test += test_int.bpf.o

target-int-remove-test-skel := int_remover_test.skel.h

# INT Inserter Targets

obj-bpf-int-insert := int_push.bpf.o
obj-bpf-int-insert += tcp.bpf.o
obj-bpf-int-insert += udp.bpf.o
obj-bpf-int-insert += ip.bpf.o
obj-bpf-int-insert += ethernet.bpf.o
obj-bpf-int-insert += driver.bpf.o
obj-bpf-int-insert += redirect_entry.bpf.o

target-int-insert-skel := int_inserter.skel.h

# XDP Test INT Inserter Targets

obj-bpf-int-insert-test := $(obj-bpf-int-insert)
obj-bpf-int-insert-test += test_int.bpf.o

target-int-insert-test-skel := int_inserter_test.skel.h

# XDP Redirect Targets

obj-bpf-redirect := redirect_entry.bpf.o

target-redirect-skel := redirect.skel.h

# Generic Targets

obj-bpf-generic := no_op.bpf.o 

obj-bpf := $(obj-bpf-generic)
obj-bpf += $(obj-bpf-redirect)
obj-bpf += $(obj-bpf-int-insert)
obj-bpf += $(obj-bpf-int-remove)
obj-bpf += $(obj-bpf-int-remove-test)

target-test-skel := $(target-int-remove-test-skel)
target-test-skel += $(target-int-insert-test-skel)

target-skel := $(target-redirect-skel)
target-skel += $(target-int-insert-skel)
target-skel += $(target-int-remove-skel)
target-skel += $(target-test-skel)

# Rules

phony += all

all: $(target-skel)

phony += test

test: $(target-test-skel)

dep-bpf := $(obj-bpf:.bpf.o=.bpf.d)

$(dep-bpf): %.bpf.d: %.c
	$(COMPILE.test.c) $< -M -MT '$(@:.d=.o) $@' > $@

-include $(dep-bpf)

target-bpf := $(target-skel:.skel.h=.bpf.o)

$(target-int-remove-skel:.skel.h=.bpf.o): $(obj-bpf-int-remove) $(obj-bpf-generic)

$(target-int-remove-test-skel:.skel.h=.bpf.o): $(obj-bpf-int-remove-test) $(obj-bpf-generic)

$(target-int-insert-skel:.skel.h=.bpf.o): $(obj-bpf-int-insert) $(obj-bpf-generic)

$(target-int-insert-test-skel:.skel.h=.bpf.o): $(obj-bpf-int-insert-test) $(obj-bpf-generic)

$(target-redirect-skel:.skel.h=.bpf.o): $(obj-bpf-redirect) $(obj-bpf-generic)

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