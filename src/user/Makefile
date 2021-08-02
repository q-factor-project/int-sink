
# INT remover Targets

obj-user-remover-exec := int_remover.o sample_processor.o

target-remover-exec := int_remover

# INT Inserter Targets

obj-user-inserter-exec := int_inserter.o

target-inserter-exec := int_inserter

# XDP Redirect Targets

obj-user-redirect-exec := redirect.o

target-redirect-exec := redirect

# Test Targets

obj-user-test := int_remover_test.o

target-test := int_remover_test

# Generic Targets

obj-user := $(obj-user-remover-exec) $(obj-user-inserter-exec) $(obj-user-redirect-exec) $(obj-user-test)

targets := $(target-remover-exec) $(target-inserter-exec) $(target-redirect-exec)

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

$(target-test): $(obj-user-test) $(OBJECT_LIBBPF)

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