CC = clang
ASM = clang
CFLAGS = -O3 -march=native -mtune=native -flto -fomit-frame-pointer \
         -I./src/include -DSIMD_BENCHMARK=1
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
# Remove duplicate simd_optimizer_c.o since it just includes simd_optimizer.c
CLEAN_C_OBJECTS = $(filter-out $(BUILDDIR)/simd_optimizer_c.o,$(C_OBJECTS))

TARGET = pcap_parser
SIMD_BENCHMARK = simd_benchmark

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
	rm -rf $(BUILDDIR) $(TARGET) $(SIMD_BENCHMARK)

test: $(TARGET)
	./test/run_tests.sh

# SIMD benchmark target (exclude main.o to avoid main() conflict)
BENCHMARK_OBJECTS = $(filter-out $(BUILDDIR)/main.o,$(CLEAN_C_OBJECTS))
$(SIMD_BENCHMARK): simd_benchmark.c $(BENCHMARK_OBJECTS) $(ASM_OBJECTS) | $(BUILDDIR)
	$(CC) $(CFLAGS) simd_benchmark.c $(BENCHMARK_OBJECTS) $(ASM_OBJECTS) -o $@ $(LDFLAGS)

benchmark: $(SIMD_BENCHMARK)
	@echo "SIMD Performance benchmark"
	./$(SIMD_BENCHMARK) --quick
	@echo "Benchmark completed - run './$(SIMD_BENCHMARK)' for full benchmark"

simd-test: $(SIMD_BENCHMARK)
	@echo "Full SIMD performance test"
	./$(SIMD_BENCHMARK)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/