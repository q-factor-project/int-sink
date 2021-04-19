obj-bpf := int_remover.bpf.o

phony :=

bpf.a: $(obj-bpf)
	$(AR) $(ARFLAGS) $@ $^

%.bpf.o: %.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h
	$(COMPILE.bpf.c) $(OUTPUT_OPTION) $<

%.bpf.ll: %.c $(OBJECT_LIBBPF) $(OUTPUT_DIR)/vmlinux.h
	$(COMPILE.bpf.c) -emit-llvm $(OUTPUT_OPTION) $<

phony += clean

clean:
	rm bpf.a
	rm $(obj-bpf)

.PHONY: $(phony)

.DELETE_ON_ERROR:

.SECONDARY: