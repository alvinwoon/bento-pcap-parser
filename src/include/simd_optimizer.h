#ifndef SIMD_OPTIMIZER_H
#define SIMD_OPTIMIZER_H

#include <stdint.h>
#include <stddef.h>

// Advanced SIMD and cache optimization functions
// Designed for high-performance IEX PCAP parsing

#ifdef __cplusplus
extern "C" {
#endif

// SIMD PCAP batch processing
// Processes multiple PCAP headers simultaneously using vectorized operations
// Returns: number of valid headers processed
uint32_t simd_parse_pcap_batch(const void* input_buffer, 
                               void* output_buffer, 
                               uint32_t header_count);

// SIMD IEX message extraction
// Vectorized pattern matching for IEX message types (0x51, 0x54, etc.)
// Returns: number of messages found
uint32_t simd_extract_iex_messages(const uint8_t* udp_payload,
                                   size_t payload_length,
                                   void* output_buffer);

// Cache-optimized chunk processor
// Optimized for large file processing (29GB+) with streaming stores
// Uses multi-level prefetching and cache-line alignment
void cache_optimized_chunk_processor(const void* source,
                                     void* destination,
                                     size_t chunk_size);

// SIMD configuration and capability detection
typedef struct {
    int has_avx2;           // x86_64: AVX2 support
    int has_avx512;         // x86_64: AVX-512 support  
    int has_neon;           // ARM64: NEON support
    int has_sve;            // ARM64: SVE support
    int cache_line_size;    // CPU cache line size
    int l1_cache_size;      // L1 cache size
    int l2_cache_size;      // L2 cache size
    int l3_cache_size;      // L3 cache size
} simd_capabilities_t;

// Detect SIMD capabilities and cache hierarchy
void detect_simd_capabilities(simd_capabilities_t* caps);

// Performance tuning parameters
typedef struct {
    size_t batch_size;          // Optimal batch size for SIMD operations
    size_t prefetch_distance;   // Optimal prefetch distance
    size_t chunk_alignment;     // Memory alignment for chunks
    int use_streaming_stores;   // Enable non-temporal stores
    int prefetch_levels;        // Number of prefetch levels
} simd_tuning_params_t;

// Get optimal tuning parameters for current hardware
void get_optimal_tuning_params(const simd_capabilities_t* caps,
                               simd_tuning_params_t* params);

// Specialized IEX message processing functions
typedef struct {
    uint64_t symbol_hash;       // CRC32 hash of symbol
    uint32_t message_type;      // IEX message type (0x51, 0x54, etc.)
    uint32_t price;             // Price in fixed-point format
    uint32_t size;              // Share/lot size
    uint64_t timestamp;         // Message timestamp
    uint32_t flags;             // Message flags
} __attribute__((packed)) simd_iex_message_t;

// SIMD quote processing with bid/ask extraction
// Processes multiple quote messages simultaneously
uint32_t simd_process_quote_batch(const uint8_t* quote_data,
                                  size_t data_length,
                                  simd_iex_message_t* output_messages,
                                  uint32_t max_messages);

// SIMD trade processing with vectorized price/size extraction
uint32_t simd_process_trade_batch(const uint8_t* trade_data,
                                  size_t data_length,
                                  simd_iex_message_t* output_messages,
                                  uint32_t max_messages);

// Cache-friendly symbol hashing using SIMD CRC32
uint64_t simd_hash_symbol(const char* symbol, size_t length);

// Memory bandwidth optimization functions
typedef struct {
    void* aligned_buffer;       // Cache-aligned buffer
    size_t buffer_size;         // Total buffer size
    size_t alignment;           // Memory alignment used
    int numa_node;              // NUMA node for allocation
} simd_memory_buffer_t;

// Allocate cache-optimized memory buffer
int alloc_simd_buffer(simd_memory_buffer_t* buffer, 
                      size_t size, 
                      size_t alignment);

// Free SIMD-optimized buffer
void free_simd_buffer(simd_memory_buffer_t* buffer);

// Performance measurement macros
#ifdef SIMD_BENCHMARK
#define SIMD_TIMER_START() \
    uint64_t _start_cycles = __builtin_readcyclecounter()

#define SIMD_TIMER_END(operation_name) \
    uint64_t _end_cycles = __builtin_readcyclecounter(); \
    printf("SIMD %s: %llu cycles\n", operation_name, _end_cycles - _start_cycles)
#else
#define SIMD_TIMER_START()
#define SIMD_TIMER_END(operation_name)
#endif

// Architecture-specific optimizations
#ifdef __aarch64__
    // ARM64-specific NEON optimizations
    #define SIMD_VECTOR_SIZE 16     // 128-bit NEON vectors
    #define SIMD_CACHE_LINE 64      // ARM64 cache line size
    #include <arm_neon.h>
#elif defined(__x86_64__)
    // x86_64-specific AVX2/AVX-512 optimizations
    #define SIMD_VECTOR_SIZE 32     // 256-bit AVX2 vectors
    #define SIMD_CACHE_LINE 64      // x86_64 cache line size
    #include <immintrin.h>
#endif

// Compiler optimization hints
#define SIMD_LIKELY(x)      __builtin_expect(!!(x), 1)
#define SIMD_UNLIKELY(x)    __builtin_expect(!!(x), 0)
#define SIMD_PREFETCH(addr) __builtin_prefetch((addr), 0, 3)
#define SIMD_ALIGN(n)       __attribute__((aligned(n)))
#define SIMD_HOT            __attribute__((hot))
#define SIMD_COLD           __attribute__((cold))

#ifdef __cplusplus
}
#endif

#endif // SIMD_OPTIMIZER_H