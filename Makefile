CC = clang
ASM = clang
CFLAGS = -O3 -march=native -mtune=native -flto -fomit-frame-pointer
ASMFLAGS = -c
LDFLAGS = 

SRCDIR = src
BUILDDIR = build
ASMDIR = $(SRCDIR)/asm
CDIR = $(SRCDIR)/c
INCDIR = $(SRCDIR)/include

ASM_SOURCES = $(wildcard $(ASMDIR)/*.s)
C_SOURCES = $(wildcard $(CDIR)/*.c)
ASM_OBJECTS = $(ASM_SOURCES:$(ASMDIR)/%.s=$(BUILDDIR)/%.o)
C_OBJECTS = $(C_SOURCES:$(CDIR)/%.c=$(BUILDDIR)/%.o)

TARGET = pcap_parser

.PHONY: all clean test benchmark

all: $(TARGET)

$(TARGET): $(ASM_OBJECTS) $(C_OBJECTS) | $(BUILDDIR)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/%.o: $(ASMDIR)/%.s | $(BUILDDIR)
	$(ASM) $(ASMFLAGS) -o $@ $<

$(BUILDDIR)/%.o: $(CDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) $(TARGET)

test: $(TARGET)
	./test/run_tests.sh

benchmark: $(TARGET)
	./test/benchmark.sh

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/