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

void print_hex_analysis(const uint8_t *data, size_t offset, const char *label) {
    printf("\n%s at offset %zu:\n", label, offset);
    printf("Hex: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", data[offset + i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
    
    printf("ASCII: ");
    for (int i = 0; i < 32; i++) {
        uint8_t c = data[offset + i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n");
    
    // Show individual field interpretations
    printf("Bytes 0-3 as uint32: %u\n", *(uint32_t*)(data + offset));
    printf("Bytes 4-7 as uint32: %u\n", *(uint32_t*)(data + offset + 4));
    printf("Bytes 8-15 as symbol: ");
    for (int i = 8; i < 16; i++) {
        uint8_t c = data[offset + i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n");
}

int main() {
    int fd = open("chunk_01.pcap", O_RDONLY);
    if (fd == -1) {
        perror("open chunk_01.pcap");
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
    
    uint8_t *data_ptr = data;
    size_t remaining = st.st_size;
    
    // Skip Section Header Block
    uint32_t block_len = *((uint32_t *)(data_ptr + 4));
    data_ptr += block_len;
    remaining -= block_len;
    
    // Find first large packet
    while (remaining > 8) {
        uint32_t block_type = *((uint32_t *)data_ptr);
        block_len = *((uint32_t *)(data_ptr + 4));
        
        if (block_type == PCAPNG_EPB_TYPE && block_len >= sizeof(pcapng_epb_t)) {
            pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
            uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
            
            if (epb->captured_len > 1000) {
                printf("=== IEX Message Structure Analysis ===\n");
                printf("Packet size: %u bytes\n", epb->captured_len);
                
                const uint8_t *udp_payload = packet_data + 42;
                size_t payload_len = epb->captured_len - 42;
                
                printf("UDP payload size: %zu bytes\n", payload_len);
                
                // Show first 64 bytes of UDP payload
                printf("\nFirst 64 bytes of UDP payload:\n");
                for (int i = 0; i < 64 && i < payload_len; i++) {
                    printf("%02x ", udp_payload[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n");
                
                // Look for potential message starts (letters A-Z)
                printf("\nPotential message locations:\n");
                for (size_t i = 0; i < payload_len - 32; i++) {
                    if (udp_payload[i] >= 'A' && udp_payload[i] <= 'Z') {
                        // Check if this might be a symbol start
                        int looks_like_symbol = 1;
                        for (int j = 1; j < 4; j++) {
                            uint8_t c = udp_payload[i + j];
                            if (c < 'A' || c > 'Z') {
                                looks_like_symbol = 0;
                                break;
                            }
                        }
                        
                        if (looks_like_symbol) {
                            printf("\nPossible symbol at offset %zu: ", i);
                            for (int j = 0; j < 8; j++) {
                                uint8_t c = udp_payload[i + j];
                                printf("%c", (c >= 'A' && c <= 'Z') ? c : '.');
                            }
                            printf("\n");
                            
                            // Show context around this potential symbol
                            print_hex_analysis(udp_payload, i >= 16 ? i - 16 : 0, "Context");
                            
                            break; // Just show first one
                        }
                    }
                }
                
                break; // Just analyze first large packet
            }
        }
        
        data_ptr += block_len;
        remaining -= block_len;
    }
    
    munmap(data, st.st_size);
    close(fd);
    return 0;
}