
# INT remover Targets

obj-user-remover-exec := int_remover.o sample_processor.o

target-remover-exec := int_remover

# Remover Test Targets

obj-user-remover-test := int_remover_test.o

target-remover-test := int_remover_test

# INT Inserter Targets

obj-user-inserter-exec := int_inserter.o

target-inserter-exec := int_inserter

# Inserter Test Targets

obj-user-inserter-test := int_inserter_test.o

target-inserter-test := int_inserter_test

# XDP Redirect Targets

obj-user-redirect-exec := redirect.o

target-redirect-exec := redirect

# Generic XDP Attach Program

obj-user-attach-exec := generic_attach.o

target-attach-exec := xdp_attach

# Generic Targets

obj-user := $(obj-user-remover-exec) $(obj-user-inserter-exec) $(obj-user-redirect-exec) $(obj-user-remover-test) $(obj-user-inserter-test) $(obj-user-attach-exec)

target-test := $(target-remover-test) $(target-inserter-test)

targets := $(target-remover-exec) $(target-inserter-exec) $(target-redirect-exec) $(target-attach-exec)

# Rules

phony += all

all: $(targets) test

phony += test

test: $(target-test)

dep-user := $(obj-user:.o=.d)

$(dep-user): %.d: %.c
	$(COMPILE.test.c) $< -M -MT '$(@:.d=.o) $@' > $@

-include $(dep-user)

$(target-remover-exec): $(obj-user-remover-exec) $(OBJECT_LIBBPF)

$(target-inserter-exec): $(obj-user-inserter-exec) $(OBJECT_LIBBPF)

$(target-redirect-exec): $(obj-user-redirect-exec) $(OBJECT_LIBBPF)

$(target-remover-test): $(obj-user-remover-test) $(OBJECT_LIBBPF)

$(target-inserter-test): $(obj-user-inserter-test) $(OBJECT_LIBBPF)

$(target-attach-exec): $(obj-user-attach-exec) $(OBJECT_LIBBPF)

$(targets): 
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(obj-user): %.o: %.c $(OBJECT_LIBBPF)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

phony += clean

clean-targets += $(targets) $(target-test) $(obj-user) $(dep-user)

clean:
	-rm -f $(clean-targets)

.PHONY: $(phony)

.DELETE_ON_ERROR:

.SECONDARY: