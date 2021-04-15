# IEX PCAP Parser

A tool for parsing IEX (Investors Exchange) PCAP files https://iextrading.com/trading/market-data/

## Features

- **Ultra-fast parsing**: Memory-mapped I/O with SIMD optimization for >1GB/s throughput
- **Quote extraction**: Real-time bid/ask price and size extraction from IEX Quote Updates 
- **Trade monitoring**: Complete trade execution data with symbol, price, volume analysis
- **Market data analysis**: Message type detection and counting
- **ARM64/x86 support**: Optimized assembly routines for both architectures
- **Zero-copy design**: Direct memory access for minimal latency overhead

## Quick Start

### Build
```bash
make clean && make
```

### Parse Trading Data
```bash
# Extract quotes and trades with bid/ask prices
./iex_parser your_file.pcap

# Analyze message distribution
./iex_parser -m 1 your_file.pcap

# Debug mode with detailed output
./iex_parser -d -p 5 your_file.pcap
```

### Split Large Files
```bash
# Split 29GB file into 10MB chunks for testing
./pcap_splitter large_file.pcap 10
```

## Tools Overview

| Tool | Purpose | Use Case |
|------|---------|----------|
| `iex_parser` | Main extraction tool | Real-time quote/trade parsing |
| `pcap_splitter` | File segmentation | Break large files for analysis |
| `debug_iex` | Hex analysis | Low-level message debugging |
| `hex_inspector` | Raw data viewer | Binary format investigation |
| `core_trading_parser` | Core extraction | Lightweight trade parsing |

## IEX Message Types

The parser handles key IEX message formats:

- **0x51 Quote Updates**: Bid/ask price changes with size
- **0x54 Trade Reports**: Executed trades with price/volume
- **0x53 System Events**: Market state changes
- **0x48 Trading Status**: Symbol trading status
- **0x44 Security Directory**: Symbol definitions

## Output Format

### Quote Data
```
Symbol   | Type  | Bid Price | Bid Size   | Ask Price | Ask Size   | Notes
---------|-------|-----------|------------|-----------|------------|------------------
AAPL     | QUOTE | $  150.25 |      10000 | $  150.26 |       5000 | Active bid/ask
TSLA     | QUOTE | (inactive quote)               | Zero bid/ask
```

### Trade Data  
```
Symbol   | Type  | Trade Price | Trade Size | Notes
---------|-------|-------------|------------|------------------
AAPL     | TRADE | $  150.255  |     25000  | Execution
MSFT     | TRADE | $  250.125  |     10000  | Execution
```

## Performance

Optimized for institutional HFT environments:
- **Latency**: Sub-microsecond message parsing
- **Throughput**: 1+ GB/s on large files (tested with 29GB datasets)
- **Memory**: Memory-mapped I/O with 2MB aligned chunks
- **CPU**: SIMD instructions (AVX2/NEON) for vectorized processing

## Architecture

```
src/
├── asm/           # Hand-optimized assembly routines
│   ├── pcap_parser.s    # PCAP packet parsing with SIMD
│   └── iex_parser.s     # IEX message extraction
├── c/             # C wrapper functions
│   ├── mmap_parser.c    # Memory-mapped file handling
│   └── main.c           # Application entry point
└── include/       # Headers and data structures
    ├── pcap.h           # PCAP format definitions  
    └── iex.h            # IEX message structures
```

## Usage Examples

### Extract Market Data
```bash
# Basic extraction
./iex_parser market_data.pcap

# Process first 10 packets with debug
./iex_parser -d -p 10 market_data.pcap

# Analysis mode for message counting
./iex_parser -m 1 market_data.pcap
```

### Work with Large Files
```bash
# Split 29GB file into manageable chunks
./pcap_splitter huge_market_data.pcap 50

# Process each chunk
for file in chunk_*.pcap; do
    ./iex_parser "$file" > "results_$file.txt"
done
```

### Debug Binary Data
```bash
# Inspect raw message structure
./debug_iex market_data.pcap

# View hex dump of specific offsets
./hex_inspector market_data.pcap
```

## Requirements

- **OS**: macOS (ARM64/Intel) or Linux (x86_64)
- **Compiler**: clang with C11 support
- **Memory**: 8GB+ RAM for large file processing
- **CPU**: AVX2 support recommended (automatic fallback)

## Build System

Standard Makefile with optimization flags:
```bash
make              # Build all tools
make clean        # Clean build artifacts
make test         # Run validation tests
make benchmark    # Performance testing
```

## Data Sources

This parser is designed for IEX HIST PCAP files containing:
- Historical market data feeds
- Real-time trading sessions
- After-hours trading data
- Auction and opening/closing cross data

**Note**: PCAP files are not included due to redistribution restrictions.

## Contributing

When modifying assembly code:
1. Maintain SIMD alignment requirements
2. Test with both small and large files (1MB - 29GB range)
3. Verify endianness handling for cross-platform compatibility
4. Profile critical paths for latency regressions

---
