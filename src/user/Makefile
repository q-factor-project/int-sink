
# Regular Targets

obj-user-exec := int_remover.o sample_processor.o

target-exec := int_remover

# Test Targets

obj-user-test := test.o

target-test := test

# Generic Targets

obj-user := $(obj-user-exec) $(obj-user-test)

targets := $(target-exec) $(target-test)

# Rules

phony += all

all: $(target-exec)

dep-user := $(obj-user:.o=.d) test.d

$(dep-user): %.d: %.c
	$(COMPILE.test.c) $< -M -MT '$(@:.d=.o) $@' > $@

-include $(dep-user)

$(target-exec): $(obj-user-exec) $(OBJECT_LIBBPF)

$(target-test): $(obj-user-test) $(OBJECT_LIBBPF)

$(targets): 
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(obj-user): %.o: %.c $(OBJECT_LIBBPF)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

phony += clean

clean-targets += $(targets) $(obj-user) $(dep-user)

clean:
	-rm -f $(clean-targets)

.PHONY: $(phony)

.DELETE_ON_ERROR:

.SECONDARY: