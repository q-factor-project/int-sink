#Input Directories

LIBBPF_SRCDIR ?= libbpf/src

SRCDIR ?= src

SCRIPTSDIR := scripts

# Output Directories

DESTDIR := $(abspath out)

## Output Subdirectories

PREFIX ?= 
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
UAPIDIR ?= $(PREFIX)/include

LIBBPF := $(DESTDIR)$(LIBDIR)/libbpf.a

libraries := $(LIBBPF)

# Compilation Variables

CC = clang

CXX = clang -x c++ -std=c++17

BPFTOOL = bpftool

COMPILE.bpf.c = $(CC) $(BPFCFLAGS) $(CPPFLAGS) $(BPF_TARGET_ARCH) -c
COMPILE.bpf.cc = $(CXX) $(BPFCXXFLAGS) $(CPPFLAGS) $(BPF_TARGET_ARCH) -c

LINK.bpf.o = $(BPFTOOL) gen object

RM = rm -rf

# Compilation flags

BPFCFLAGS :=
BPFCFLAGS += -Wall
BPFCFLAGS += -Wno-unused-value
BPFCFLAGS += -Wno-pointer-sign
BPFCFLAGS += -Wno-compare-distinct-pointer-types
BPFCFLAGS += -Werror
BPFCFLAGS += -O2
BPFCFLAGS += -g

BPFCXXFLAGS :=
BPFCXXFLAGS += -Wall
BPFCXXFLAGS += -Wno-unused-value
BPFCXXFLAGS += -Wno-pointer-sign
BPFCXXFLAGS += -Wno-compare-distinct-pointer-types
BPFCXXFLAGS += -Werror
BPFCXXFLAGS += -fno-exceptions
BPFCXXFLAGS += -O2
BPFCXXFLAGS += -g

BPF_TARGET_ARCH = -target bpf


LDFLAGS += -L$(DESTDIR)$(LIBDIR)
LDLIBS += -l:libbpf.a
LDLIBS += -lelf
LDLIBS += -lz

CPPFLAGS += -I$(DESTDIR)$(INCLUDEDIR)
CPPFLAGS += -I$(SRCDIR)

# Build Tasks

all: $(libraries)

$(LIBBPF): | $(DESTDIR)
	$(MAKE) -C $(LIBBPF_SRCDIR) DESTDIR=$(DESTDIR) LIBDIR=$(LIBDIR) INCLUDEDIR=$(INCLUDEDIR) UAPIDIR=$(UAPIDIR) PREFIX=$(PREFIX) install

$(DESTDIR):
	mkdir -p $@

targets :=
clean-targets :=

src = $(SRCDIR)/bpf

include $(SCRIPTSDIR)/Makefile

src = $(SRCDIR)/user

include $(SCRIPTSDIR)/Makefile

all: $(targets)

# Clean Tasks

clean_libbpf:
	$(MAKE) -C $(LIBBPF_SRCDIR) clean

clean_outdir:
	$(RM) $(DESTDIR)

clearn_objects:
	$(RM) $(clean-targets)

clean: clean_libbpf clean_outdir clearn_objects

