#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define PCAPNG_MAGIC 0x0a0d0d0a
#define PCAPNG_EPB_TYPE 0x00000006

typedef struct {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
} __attribute__((packed)) pcapng_epb_t;

// IEX message header structure
typedef struct {
    uint8_t message_type;
    uint64_t timestamp;  // IEX timestamp
    uint64_t symbol;     // 8-byte symbol (will decode separately)
} __attribute__((packed)) iex_header_t;

// Clean symbol extraction
void extract_symbol(const uint8_t *symbol_bytes, char *output) {
    int len = 0;
    for (int i = 0; i < 8; i++) {
        if (symbol_bytes[i] > 0x20 && symbol_bytes[i] <= 0x7E) { // printable ASCII
            output[len++] = symbol_bytes[i];
        }
    }
    output[len] = '\0';
}

// Convert IEX timestamp to readable format
void format_timestamp(uint64_t iex_time, char *output) {
    // IEX timestamps are in nanoseconds since midnight
    uint64_t hours = iex_time / (3600ULL * 1000000000);
    uint64_t minutes = (iex_time % (3600ULL * 1000000000)) / (60ULL * 1000000000);
    uint64_t seconds = (iex_time % (60ULL * 1000000000)) / 1000000000;
    uint64_t nanos = iex_time % 1000000000;
    
    snprintf(output, 32, "%02llu:%02llu:%02llu.%09llu", hours, minutes, seconds, nanos);
}

// Parse Trade Report message (0x54)
void parse_trade_report(const uint8_t *data, size_t offset) {
    const uint8_t *msg = &data[offset];
    
    // IEX Trade Report format:
    // Byte 0: Message Type (0x54)
    // Bytes 1-8: Timestamp  
    // Bytes 9-16: Symbol
    // Bytes 17-20: Price (32-bit, scaled)
    // Bytes 21-24: Size
    // Byte 25: Sale Condition
    
    if (msg[0] != 0x54) return;
    
    uint64_t timestamp = *(uint64_t*)(msg + 1);
    const uint8_t *symbol_bytes = msg + 9;
    uint32_t price_raw = *(uint32_t*)(msg + 17);
    uint32_t size = *(uint32_t*)(msg + 21);
    uint8_t sale_condition = msg[25];
    
    char symbol[16];
    char time_str[32];
    extract_symbol(symbol_bytes, symbol);
    format_timestamp(timestamp, time_str);
    
    // IEX prices are in 1/10000 of a dollar
    double price = (double)price_raw / 10000.0;
    
    // Only show reasonable prices and valid symbols
    if (price > 0.01 && price < 10000.0 && strlen(symbol) > 0) {
        printf("TRADE | %-8s | %s | $%8.4f | %10u | %c\n",
               symbol, time_str, price, size, 
               (sale_condition >= 32 && sale_condition <= 126) ? sale_condition : ' ');
    }
}

// Parse Quote Update message (0x51)  
void parse_quote_update(const uint8_t *data, size_t offset) {
    const uint8_t *msg = &data[offset];
    
    // IEX Quote Update format:
    // Byte 0: Message Type (0x51)
    // Bytes 1-8: Timestamp
    // Bytes 9-16: Symbol  
    // Bytes 17-20: Bid Price
    // Bytes 21-24: Bid Size
    // Bytes 25-28: Ask Price
    // Bytes 29-32: Ask Size
    
    if (msg[0] != 0x51) return;
    
    uint64_t timestamp = *(uint64_t*)(msg + 1);
    const uint8_t *symbol_bytes = msg + 9;
    uint32_t bid_price_raw = *(uint32_t*)(msg + 17);
    uint32_t bid_size = *(uint32_t*)(msg + 21);
    uint32_t ask_price_raw = *(uint32_t*)(msg + 25);
    uint32_t ask_size = *(uint32_t*)(msg + 29);
    
    char symbol[16];
    char time_str[32];
    extract_symbol(symbol_bytes, symbol);
    format_timestamp(timestamp, time_str);
    
    double bid_price = (double)bid_price_raw / 10000.0;
    double ask_price = (double)ask_price_raw / 10000.0;
    
    // Show valid quotes
    if (bid_price > 0.01 && ask_price > 0.01 && ask_price > bid_price && strlen(symbol) > 0) {
        double spread = ask_price - bid_price;
        printf("QUOTE | %-8s | %s | $%8.4f x %6u | $%8.4f x %6u | Spread:$%.4f\n",
               symbol, time_str, bid_price, bid_size, ask_price, ask_size, spread);
    }
}

// Parse Official Price message (0x58)
void parse_official_price(const uint8_t *data, size_t offset) {
    const uint8_t *msg = &data[offset];
    
    if (msg[0] != 0x58) return;
    
    uint64_t timestamp = *(uint64_t*)(msg + 1);
    const uint8_t *symbol_bytes = msg + 9;
    uint32_t official_price_raw = *(uint32_t*)(msg + 17);
    
    char symbol[16];
    char time_str[32];
    extract_symbol(symbol_bytes, symbol);
    format_timestamp(timestamp, time_str);
    
    double official_price = (double)official_price_raw / 10000.0;
    
    if (official_price > 0.01 && strlen(symbol) > 0) {
        printf("OFFCL | %-8s | %s | $%8.4f (Official)\n",
               symbol, time_str, official_price);
    }
}

// Analyze UDP payload for core trading messages
void parse_core_trading_data(const uint8_t *udp_payload, size_t len) {
    int trade_count = 0, quote_count = 0, official_count = 0;
    
    // Look for properly aligned IEX messages
    for (size_t i = 0; i < len - 35; i++) {
        uint8_t msg_type = udp_payload[i];
        
        // Verify this looks like a real message by checking symbol area
        if (i + 35 < len) {
            const uint8_t *symbol_area = &udp_payload[i + 9];
            
            // Check if symbol starts with a letter (basic validation)
            if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                switch (msg_type) {
                    case 0x54: // Trade Report
                        if (trade_count < 10) {
                            parse_trade_report(udp_payload, i);
                            trade_count++;
                        }
                        break;
                        
                    case 0x51: // Quote Update
                        if (quote_count < 5) {
                            parse_quote_update(udp_payload, i);
                            quote_count++;
                        }
                        break;
                        
                    case 0x58: // Official Price
                        if (official_count < 5) {
                            parse_official_price(udp_payload, i);
                            official_count++;
                        }
                        break;
                }
            }
        }
    }
    
    printf("\nParsed: %d trades, %d quotes, %d official prices\n", 
           trade_count, quote_count, official_count);
}

int main(int argc, char *argv[]) {
    const char *filename = (argc > 1) ? argv[1] : "chunk_01.pcap";
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        perror("Failed to open file");
        return 1;
    }
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        close(fd);
        return 1;
    }
    
    uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    
    printf("=== Core Trading Data Parser ===\n");
    printf("File: %s (%.2f MB)\n\n", filename, (double)st.st_size / (1024*1024));
    
    uint8_t *data_ptr = data;
    size_t remaining = st.st_size;
    
    // Skip Section Header Block
    uint32_t block_len = *((uint32_t *)(data_ptr + 4));
    data_ptr += block_len;
    remaining -= block_len;
    
    int large_packets_processed = 0;
    
    printf("Type  | Symbol   | Time              | Price/Bid    | Size/Ask    | Extra\n");
    printf("------|----------|-------------------|--------------|-------------|------------------\n");
    
    // Process packets
    while (remaining > 8 && large_packets_processed < 5) {
        uint32_t block_type = *((uint32_t *)data_ptr);
        block_len = *((uint32_t *)(data_ptr + 4));
        
        if (block_len < 12 || block_len > remaining) break;
        
        if (block_type == PCAPNG_EPB_TYPE && block_len >= sizeof(pcapng_epb_t)) {
            pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
            uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
            
            // Focus on large packets with trading data
            if (epb->captured_len > 1000) {
                const uint8_t *udp_payload = packet_data + 42;
                size_t payload_len = epb->captured_len - 42;
                
                printf("\n--- Packet %d (%u bytes) ---\n", 
                       large_packets_processed + 1, epb->captured_len);
                parse_core_trading_data(udp_payload, payload_len);
                large_packets_processed++;
            }
        }
        
        data_ptr += block_len;
        remaining -= block_len;
    }
    
    munmap(data, st.st_size);
    close(fd);
    return 0;
}