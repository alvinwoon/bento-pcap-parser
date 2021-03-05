#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "pcap.h"
#include "iex.h"

int init_mmap_parser(const char *filename, mmap_context_t *ctx) {
    struct stat st;
    
    ctx->fd = open(filename, O_RDONLY);
    if (ctx->fd == -1) {
        perror("open");
        return -1;
    }
    
    if (fstat(ctx->fd, &st) == -1) {
        perror("fstat");
        close(ctx->fd);
        return -1;
    }
    
    ctx->size = st.st_size;
    
    // Memory map file (macOS doesn't support MAP_POPULATE/MAP_HUGETLB)
    ctx->data = mmap(NULL, ctx->size, PROT_READ, MAP_PRIVATE, ctx->fd, 0);
    
    if (ctx->data == MAP_FAILED) {
        perror("mmap");
        close(ctx->fd);
        return -1;
    }
    
    // Advise sequential access
    madvise(ctx->data, ctx->size, MADV_SEQUENTIAL | MADV_WILLNEED);
    
    ctx->offset = 0;
    return 0;
}

void cleanup_mmap_parser(mmap_context_t *ctx) {
    if (ctx->data != MAP_FAILED) {
        munmap(ctx->data, ctx->size);
    }
    if (ctx->fd != -1) {
        close(ctx->fd);
    }
}

int parse_pcap_file(mmap_context_t *ctx) {
    uint32_t *magic = (uint32_t *)ctx->data;
    
    // Validate PCAP/PCAPNG header
    if (!validate_pcap_header_asm(ctx->data)) {
        fprintf(stderr, "Invalid PCAP file format\n");
        return -1;
    }
    
    printf("PCAP file size: %zu bytes\n", ctx->size);
    
    uint8_t *data_ptr;
    size_t remaining;
    
    if (*magic == PCAPNG_MAGIC) {
        printf("Detected PCAPNG format\n");
        data_ptr = (uint8_t *)ctx->data;
        remaining = ctx->size;
        
        // Read Section Header Block length safely
        if (remaining < 12) {
            fprintf(stderr, "File too small for pcapng header\n");
            return -1;
        }
        
        uint32_t block_len = *((uint32_t *)(data_ptr + 4));
        printf("Section Header Block length: %u bytes\n", block_len);
        
        if (block_len > remaining || block_len < 28) {
            fprintf(stderr, "Invalid SHB length: %u\n", block_len);
            return -1;
        }
        
        data_ptr += block_len;
        remaining -= block_len;
    } else {
        printf("Detected classic PCAP format\n");
        pcap_header_t *header = (pcap_header_t *)ctx->data;
        printf("Network type: %u\n", header->network);
        data_ptr = (uint8_t *)ctx->data + sizeof(pcap_header_t);
        remaining = ctx->size - sizeof(pcap_header_t);
    }
    
    message_batch_t batch = {0};
    uint64_t total_packets = 0;
    uint64_t total_messages = 0;
    
    // Process in chunks for better cache performance
    while (remaining > 16) {  // Need at least 16 bytes for any packet
        size_t chunk_size = (remaining > PCAP_CHUNK_SIZE) ? PCAP_CHUNK_SIZE : remaining;
        
        // Reset batch for this chunk
        batch.count = 0;
        
        printf("Processing chunk: %zu bytes, remaining: %zu\n", chunk_size, remaining);
        
        // For pcapng, we need different parsing logic
        if (*magic == PCAPNG_MAGIC) {
            // Parse pcapng blocks
            uint8_t *chunk_end = data_ptr + chunk_size;
            uint64_t packets_in_chunk = 0;
            
            while (data_ptr + 8 <= chunk_end) {
                uint32_t block_type = *((uint32_t *)data_ptr);
                uint32_t block_len = *((uint32_t *)(data_ptr + 4));
                
                if (block_len < 12 || data_ptr + block_len > chunk_end) {
                    break; // Invalid or incomplete block
                }
                
                if (block_type == PCAPNG_EPB_TYPE) {
                    // Enhanced Packet Block - contains actual network data
                    if (block_len >= sizeof(pcapng_epb_t)) {
                        pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
                        uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
                        
                        // Call IEX parser on the packet data
                        if (epb->captured_len > 0 && epb->captured_len < 65536) {
                            // Process all packets for IEX messages
                            uint32_t msg_count = extract_iex_messages_asm(packet_data, epb->captured_len, &batch);
                            batch.count += msg_count;  // Update count in C code
                            
                            // Display sample trading data from large packets
                            static int trading_samples_shown = 0;
                            if (epb->captured_len > 1000 && trading_samples_shown < 2) {
                                trading_samples_shown++;
                                
                                printf("\n=== Sample Trading Data from Packet %d ===\n", trading_samples_shown);
                                
                                const uint8_t *udp_payload = packet_data + 42;
                                size_t payload_len = epb->captured_len - 42;
                                
                                int trade_samples = 0;
                                printf("TRADES:\n");
                                
                                // Look for trade messages (0x54)
                                for (size_t i = 0; i < payload_len - 30 && trade_samples < 5; i++) {
                                    if (udp_payload[i] == 0x54) {
                                        // Find symbol after the 0x54 marker
                                        for (int offset = 1; offset <= 5; offset++) {
                                            if (i + offset + 15 < payload_len) {
                                                const uint8_t *symbol_area = &udp_payload[i + offset];
                                                if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                                                    // Extract symbol
                                                    char ticker[16] = {0};
                                                    int len = 0;
                                                    for (int j = 0; j < 8; j++) {
                                                        if (symbol_area[j] >= 'A' && symbol_area[j] <= 'Z') {
                                                            ticker[len++] = symbol_area[j];
                                                        } else if (symbol_area[j] >= '0' && symbol_area[j] <= '9') {
                                                            ticker[len++] = symbol_area[j];
                                                        } else if (symbol_area[j] == '+' || symbol_area[j] == '-') {
                                                            ticker[len++] = symbol_area[j];
                                                        } else break;
                                                    }
                                                    
                                                    if (len > 0) {
                                                        // Extract price and size
                                                        uint32_t price_raw = *(uint32_t*)(symbol_area + 8);
                                                        uint32_t size = *(uint32_t*)(symbol_area + 12);
                                                        double price = (double)price_raw / 100.0; // Adjusted scaling
                                                        
                                                        if (price > 0.01 && price < 1000.0) {
                                                            printf("  %-8s  $%8.2f  %10u shares\n", ticker, price, size);
                                                            trade_samples++;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                printf("  (%d trade samples shown)\n", trade_samples);
                            }
                            packets_in_chunk++;
                        }
                    }
                }
                
                data_ptr += block_len;
                remaining -= block_len;
            }
            
            total_packets += packets_in_chunk;
            total_messages += batch.count;
            printf("Processed %llu packets, %u messages in chunk\n", packets_in_chunk, batch.count);
            
            // Continue to next chunk
            if (remaining <= 16) break;
            continue;
        } else {
            // Parse chunk with assembly optimizations  
            parse_pcap_chunk_asm(data_ptr, chunk_size, &batch);
            total_packets += 1;  // placeholder
        }
        
        // This line is handled separately for pcapng above
        
        // Process parsed messages (write to file, send to trading system, etc.)
        for (uint32_t i = 0; i < batch.count; i++) {
            parsed_message_t *msg = &batch.messages[i];
            
            // Example: print high-value trades
            if (msg->message_type == IEX_TRADE_REPORT && msg->price > 10000) {
                printf("High-value trade: symbol_hash=%llx, price=%u, size=%u, side=%c\n",
                       msg->symbol_hash, msg->price, msg->size, msg->side);
            }
        }
        
        data_ptr += chunk_size;
        remaining -= chunk_size;
        
        // Progress update for large files
        if (total_packets % 1000000 == 0) {
            printf("Processed %llu packets, %llu messages\n", total_packets, total_messages);
        }
    }
    
    printf("Final stats: %llu packets, %llu messages parsed\n", total_packets, total_messages);
    return 0;
}