

target-obj :=
multi-obj :=
real-obj :=

target-bpf-obj :=
multi-bpf-obj :=
real-bpf-obj :=

obj := $(src)

-include $(src)/Makefile

# Expand $(foo-objs) $(foo-y) etc. by replacing their individuals
suffix-search = $(strip $(foreach s, $3, $($(1:%$(strip $2)=%$s))))
# List composite targets that are constructed by combining other targets
multi-search = $(sort $(foreach m, $1, $(if $(call suffix-search, $m, $2, $3 -), $m)))
# List primitive targets that are compiled from source files
real-search = $(foreach m, $1, $(if $(call suffix-search, $m, $2, $3 -), $(call suffix-search, $m, $2, $3), $m))

multi-obj := $(call multi-search, $(target-obj), .o, -objs) $(call multi-search, $(target-program), , -objs)
real-obj := $(call real-search, $(target-obj), .o, -objs) $(call real-search, $(target-program), , -objs)

multi-bpf-obj := $(call multi-search, $(target-bpf-obj), .bpf.o, -bpf-objs)
real-bpf-obj := $(call real-search, $(target-bpf-obj), .bpf.o, -bpf-objs)

target-program := $(addprefix $(obj)/, $(target-program))
target-obj := $(addprefix $(obj)/, $(target-obj))
multi-obj := $(addprefix $(obj)/, $(multi-obj))
real-obj := $(addprefix $(obj)/, $(real-obj))


target-bpf-obj := $(addprefix $(obj)/, $(target-bpf-obj))
multi-bpf-obj := $(addprefix $(obj)/, $(multi-bpf-obj))
real-bpf-obj := $(addprefix $(obj)/, $(real-bpf-obj))

define multi_depend
$(foreach m, $(notdir $1), \
	$(eval $(obj)/$m: \
	$(addprefix $(obj)/, $(foreach s, $3, $($(m:%$(strip $2)=%$(s)))))))
endef

$(real-obj): $(obj)/%.o: $(src)/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(multi-obj):
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
$(call multi_depend, $(multi-obj), .o, -objs)
$(call multi_depend, $(multi-obj), , -objs)

$(real-bpf-obj): $(obj)/%.bpf.o: $(src)/%.bpf.c
	$(COMPILE.bpf.c) $(OUTPUT_OPTION) $<

$(multi-bpf-obj):
	$(LINK.bpf.o) $@ $^
$(call multi_depend, $(multi-bpf-obj), .bpf.o, -bpf-objs)

targets += $(target-obj) $(target-bpf-obj) $(target-program)

clean-targets += $(target-obj) $(target-bpf-obj) $(target-program) $(multi-obj) $(multi-bpf-obj) $(real-obj) $(real-bpf-obj)
