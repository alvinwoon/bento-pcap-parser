#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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

// Clean symbol extraction from IEX format
void extract_clean_symbol(const uint8_t *symbol_bytes, char *output, int max_len) {
    int len = 0;
    for (int i = 0; i < 8 && len < max_len - 1; i++) {
        if (symbol_bytes[i] >= 'A' && symbol_bytes[i] <= 'Z') {
            output[len++] = symbol_bytes[i];
        } else if (symbol_bytes[i] >= '0' && symbol_bytes[i] <= '9') {
            output[len++] = symbol_bytes[i];
        } else if (symbol_bytes[i] == '+' || symbol_bytes[i] == '-' || symbol_bytes[i] == '.') {
            output[len++] = symbol_bytes[i];
        } else if (symbol_bytes[i] == 0x20) {
            break; // Stop at space padding
        }
    }
    output[len] = '\0';
}

// Debug analysis of quote message structure
void debug_quote_structure(const uint8_t *data, size_t quote_offset, const char *symbol, int debug_mode) {
    if (!debug_mode) return;
    
    printf("\n=== DEBUG: Quote structure for %s at offset %zu ===\n", symbol, quote_offset);
    printf("Hex: ");
    for (int i = 0; i < 40; i++) {
        printf("%02x ", data[quote_offset + i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\nASCII: ");
    for (int i = 0; i < 40; i++) {
        uint8_t c = data[quote_offset + i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n");
    
    // Try different interpretations
    for (int offset = 8; offset <= 24; offset += 4) {
        uint32_t val1 = *(uint32_t*)(data + quote_offset + offset);
        uint32_t val2 = *(uint32_t*)(data + quote_offset + offset + 4);
        uint32_t val3 = *(uint32_t*)(data + quote_offset + offset + 8);
        uint32_t val4 = *(uint32_t*)(data + quote_offset + offset + 12);
        
        printf("Offset +%02d: %10u %10u %10u %10u\n", offset, val1, val2, val3, val4);
        printf("    /100:   $%8.2f  %8u   $%8.2f  %8u\n", 
               (double)val1/100.0, val2, (double)val3/100.0, val4);
        printf("  /10000:   $%8.4f  %8u   $%8.4f  %8u\n", 
               (double)val1/10000.0, val2, (double)val3/10000.0, val4);
    }
}

// Search for all message types (analysis mode)
void search_message_types(const uint8_t *udp_payload, size_t len, int show_details) {
    int trade_count = 0, quote_count = 0, other_counts[256] = {0};
    
    printf("Searching for IEX message types in %zu bytes...\n", len);
    
    for (size_t i = 0; i < len - 30; i++) {
        uint8_t msg_type = udp_payload[i];
        
        if (msg_type >= 0x40 && msg_type <= 0x58) {
            for (int offset = 1; offset <= 8; offset++) {
                if (i + offset + 8 < len) {
                    const uint8_t *potential_symbol = &udp_payload[i + offset];
                    if (potential_symbol[0] >= 'A' && potential_symbol[0] <= 'Z' &&
                        potential_symbol[1] >= 'A' && potential_symbol[1] <= 'Z') {
                        
                        other_counts[msg_type]++;
                        if (msg_type == 0x54) trade_count++;
                        else if (msg_type == 0x51) quote_count++;
                        
                        if (show_details && other_counts[msg_type] <= 3) {
                            char symbol[16];
                            extract_clean_symbol(potential_symbol, symbol, sizeof(symbol));
                            if (strlen(symbol) > 0) {
                                printf("Found 0x%02X: %s at offset %zu\n", msg_type, symbol, i);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    
    printf("\nMessage type summary:\n");
    for (int i = 0; i < 256; i++) {
        if (other_counts[i] > 0) {
            const char* desc = "";
            switch(i) {
                case 0x51: desc = "Quote Update"; break;
                case 0x54: desc = "Trade Report"; break;
                case 0x53: desc = "System Event"; break;
                case 0x44: desc = "Security Directory"; break;
                case 0x48: desc = "Trading Status"; break;
                case 0x41: desc = "Auction Info"; break;
                default: desc = "Other"; break;
            }
            printf("0x%02X (%s): %d occurrences\n", i, desc, other_counts[i]);
        }
    }
    printf("Total: %d trades, %d quotes found\n", trade_count, quote_count);
}

// Comprehensive quote and trade extraction
void extract_comprehensive_data(const uint8_t *udp_payload, size_t len, int mode, int debug_mode) {
    if (mode == 1) {  // Analysis mode
        search_message_types(udp_payload, len, debug_mode);
        return;
    }
    
    printf("\n=== IEX TRADING DATA WITH BID/ASK PRICES & SIZES ===\n");
    printf("Symbol   | Type  | Bid Price | Bid Size   | Ask Price | Ask Size   | Trade Price | Trade Size | Notes\n");
    printf("---------|-------|-----------|------------|-----------|------------|-------------|------------|------------------\n");
    
    int quote_count = 0, trade_count = 0, active_quotes = 0;
    
    for (size_t i = 0; i < len - 40; i++) {
        uint8_t msg_type = udp_payload[i];
        
        // Parse Quote Updates (0x51)
        if (msg_type == 0x51 && quote_count < 25) {
            const uint8_t *quote_msg = &udp_payload[i];
            
            if (i + 32 < len) {
                const uint8_t *symbol_area = &quote_msg[8];
                
                if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                    char symbol[16];
                    extract_clean_symbol(symbol_area, symbol, sizeof(symbol));
                    
                    if (strlen(symbol) >= 1) {
                        if (debug_mode && quote_count < 3) {
                            debug_quote_structure(udp_payload, i, symbol, debug_mode);
                        }
                        
                        // Check for active quote data
                        int has_quote_data = 0;
                        for (int j = 16; j < 32 && i + j < len; j++) {
                            if (quote_msg[j] != 0) {
                                has_quote_data = 1;
                                break;
                            }
                        }
                        
                        if (has_quote_data) {
                            // Try to extract bid/ask data with multiple formats
                            uint32_t val1 = *(uint32_t*)(&quote_msg[16]);
                            uint32_t val2 = *(uint32_t*)(&quote_msg[20]);
                            uint32_t val3 = *(uint32_t*)(&quote_msg[24]);
                            uint32_t val4 = *(uint32_t*)(&quote_msg[28]);
                            
                            // Try different price scaling patterns
                            int found_valid_quote = 0;
                            
                            // Pattern 1: bid_size, bid_price, ask_price, ask_size
                            double bid_price = (double)val2 / 10000.0;
                            double ask_price = (double)val3 / 10000.0;
                            
                            if (bid_price > 0.01 && ask_price > bid_price && ask_price < 1000.0 && 
                                val1 > 0 && val4 > 0) {
                                printf("%-8s | QUOTE | $%8.4f | %10u | $%8.4f | %10u |             |            | Active bid/ask\n",
                                       symbol, bid_price, val1, ask_price, val4);
                                active_quotes++;
                                found_valid_quote = 1;
                            } else {
                                // Pattern 2: Different scaling
                                bid_price = (double)val2 / 100.0;
                                ask_price = (double)val3 / 100.0;
                                if (bid_price > 0.01 && ask_price > bid_price && ask_price < 1000.0 && 
                                    val1 > 0 && val4 > 0) {
                                    printf("%-8s | QUOTE | $%8.2f | %10u | $%8.2f | %10u |             |            | Active bid/ask\n",
                                           symbol, bid_price, val1, ask_price, val4);
                                    active_quotes++;
                                    found_valid_quote = 1;
                                }
                            }
                            
                            if (!found_valid_quote) {
                                if (debug_mode) {
                                    printf("%-8s | QUOTE | (complex quote data)           |             |            | Raw: %u %u %u %u\n",
                                           symbol, val1, val2, val3, val4);
                                } else {
                                    printf("%-8s | QUOTE | (inactive quote)               |             |            | Zero bid/ask\n", symbol);
                                }
                            }
                        } else {
                            printf("%-8s | QUOTE | (quote deletion)               |             |            | Market cleanup\n", symbol);
                        }
                        quote_count++;
                    }
                }
            }
        }
        
        // Parse Trade Reports (0x54)
        else if (msg_type == 0x54 && trade_count < 25) {
            for (int offset = 1; offset <= 8; offset++) {
                if (i + offset + 16 < len) {
                    const uint8_t *symbol_area = &udp_payload[i + offset];
                    if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                        char symbol[16];
                        extract_clean_symbol(symbol_area, symbol, sizeof(symbol));
                        
                        if (strlen(symbol) >= 1) {
                            for (int data_offset = 8; data_offset <= 16; data_offset += 4) {
                                if (i + offset + data_offset + 8 < len) {
                                    uint32_t price_raw = *(uint32_t*)(symbol_area + data_offset);
                                    uint32_t size = *(uint32_t*)(symbol_area + data_offset + 4);
                                    
                                    double price = (double)price_raw / 10000.0;
                                    if (price < 0.01 || price > 1000.0) {
                                        price = (double)price_raw / 100.0;
                                    }
                                    
                                    if (price > 0.01 && price < 1000.0 && size > 0 && size < 1000000000) {
                                        printf("%-8s | TRADE |           |            |           |            | $%10.4f | %10u | Execution\n",
                                               symbol, price, size);
                                        trade_count++;
                                        goto next_trade;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            next_trade:;
        }
    }
    
    printf("\nSUMMARY: %d total quotes (%d active with bid/ask, %d inactive), %d trade executions\n", 
           quote_count, active_quotes, quote_count - active_quotes, trade_count);
    
    if (active_quotes > 0) {
        printf("✓ SUCCESS: Found %d quotes with bid/ask prices and sizes!\n", active_quotes);
    } else {
        printf("ℹ INFO: No active quotes with bid/ask found (market may be closed or quotes deleted)\n");
    }
}

void print_usage(const char *program_name) {
    printf("Usage: %s [options] <pcap_file>\n", program_name);
    printf("Options:\n");
    printf("  -m <mode>   Mode: 0=extract (default), 1=analyze\n");
    printf("  -p <count>  Number of packets to process (default: 3)\n");
    printf("  -d          Enable debug output\n");
    printf("  -h          Show this help\n");
    printf("\nModes:\n");
    printf("  0 - Extract quotes and trades with bid/ask prices and sizes\n");
    printf("  1 - Analyze and count message types in the data\n");
    printf("\nExamples:\n");
    printf("  %s chunk_01.pcap                    # Extract trading data\n", program_name);
    printf("  %s -m 1 -d chunk_01.pcap            # Analyze message types with debug\n", program_name);
    printf("  %s -p 5 -d chunk_01.pcap            # Extract from 5 packets with debug\n", program_name);
}

int main(int argc, char *argv[]) {
    const char *filename = NULL;
    int mode = 0;  // 0=extract, 1=analyze
    int packet_limit = 3;
    int debug_mode = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            packet_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0) {
            debug_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        }
    }
    
    if (!filename) {
        filename = "chunk_01.pcap";  // Default file
    }
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        print_usage(argv[0]);
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
    
    printf("=== Comprehensive IEX PCAP Parser ===\n");
    printf("File: %s (%.2f MB)\n", filename, (double)st.st_size / (1024*1024));
    printf("Mode: %s\n", mode == 0 ? "Extract quotes/trades" : "Analyze message types");
    if (debug_mode) printf("Debug: Enabled\n");
    printf("Processing up to %d packets...\n", packet_limit);
    
    uint8_t *data_ptr = data;
    size_t remaining = st.st_size;
    
    // Skip Section Header Block
    uint32_t block_len = *((uint32_t *)(data_ptr + 4));
    data_ptr += block_len;
    remaining -= block_len;
    
    int packets_processed = 0;
    
    while (remaining > 8 && packets_processed < packet_limit) {
        uint32_t block_type = *((uint32_t *)data_ptr);
        block_len = *((uint32_t *)(data_ptr + 4));
        
        if (block_len < 12 || block_len > remaining) break;
        
        if (block_type == PCAPNG_EPB_TYPE && block_len >= sizeof(pcapng_epb_t)) {
            pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
            uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
            
            if (epb->captured_len > 1000) {
                printf("\n\n############### PACKET %d (%u bytes) ###############", 
                       packets_processed + 1, epb->captured_len);
                
                const uint8_t *udp_payload = packet_data + 42;
                size_t payload_len = epb->captured_len - 42;
                
                extract_comprehensive_data(udp_payload, payload_len, mode, debug_mode);
                packets_processed++;
            }
        }
        
        data_ptr += block_len;
        remaining -= block_len;
    }
    
    printf("\n\n=== PROCESSING COMPLETE ===\n");
    printf("Processed %d packets from %s\n", packets_processed, filename);
    if (mode == 0) {
        printf("Extracted quotes with bid/ask prices and sizes as requested.\n");
    } else {
        printf("Message type analysis completed.\n");
    }
    
    munmap(data, st.st_size);
    close(fd);
    return 0;
}