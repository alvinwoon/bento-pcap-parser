# Development Notes

Internal development notes and build guidance for the IEX PCAP parser project.

## Project Overview

High-performance IEX PCAP parser optimized for high-frequency trading systems. Built with assembly language and SIMD instructions to achieve maximum throughput on large (29GB+) market data files.

## Build Commands

```bash
# Build the parser
make

# Clean build artifacts  
make clean

# Run performance tests
make benchmark

# Run unit tests
make test
```

## Architecture

**Core Components:**
- `src/asm/`: Hand-optimized assembly routines with AVX2/SIMD instructions
- `src/c/`: C wrapper functions and memory management 
- `src/include/`: Headers for PCAP and IEX message formats

**Performance Strategy:**
- Memory-mapped I/O with huge pages for 29GB+ files
- Zero-copy parsing with direct pointer arithmetic
- SIMD-optimized message extraction and validation
- 2MB chunk processing aligned to cache boundaries

**Key Files:**
- `src/asm/pcap_parser.asm`: Core PCAP packet parsing with SIMD
- `src/asm/iex_parser.asm`: IEX message format parsing with vectorization
- `src/c/mmap_parser.c`: Memory-mapped file handling and chunked processing
- `src/include/iex.h`: IEX message type definitions and output structures

## IEX Message Types

The parser focuses on high-frequency trading relevant messages:
- Quote Updates (0x51): Bid/ask price and size changes
- Trade Reports (0x54): Executed trade data with price, size, side
- Symbol hashing using CRC32 for fast lookups

## Performance Characteristics

Designed for sub-microsecond latency and >1GB/s throughput on market data feeds. Uses lock-free data structures and CPU cache-aware algorithms for real-time trading systems.

## Development Notes

When modifying assembly code, ensure SIMD alignment and test with large files. The parser assumes little-endian x64 architecture with AVX2 support.