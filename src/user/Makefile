obj-user := int_remover.o

target-exec := int_remover

phony += all

dep-user := $(obj-user:.o=.d) test.d

$(dep-user): %.d: %.c
	$(COMPILE.test.c) $< -M -MT '$(@:.d=.o) $@' > $@

-include $(dep-user)

all: $(target-exec)

$(target-exec): $(obj-user) $(OBJECT_LIBBPF)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(obj-user): %.o: %.c $(OBJECT_LIBBPF)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

test: test.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

test.o: test.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

phony += clean

clean-targets += $(target-exec) $(obj-user) $(dep-user) test.o test

clean:
	-rm -f $(clean-targets)

.PHONY: $(phony)

.DELETE_ON_ERROR:

.SECONDARY: