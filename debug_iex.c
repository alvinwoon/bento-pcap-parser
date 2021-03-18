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

void print_hex_data(const uint8_t *data, size_t len, const char *prefix) {
    printf("%s", prefix);
    for (size_t i = 0; i < len && i < 64; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n%s", prefix);
    }
    printf("\n");
}

// Forward declaration
void analyze_iex_payload(const uint8_t *udp_payload, size_t len);

void analyze_packet(const uint8_t *packet_data, size_t len) {
    printf("\n=== Packet Analysis ===\n");
    printf("Total length: %zu bytes\n", len);
    
    if (len < 42) return;
    
    // Skip to UDP payload (Ethernet 14 + IP ~20 + UDP 8 = ~42)
    const uint8_t *udp_payload = packet_data + 42;
    size_t payload_len = len - 42;
    
    printf("UDP payload length: %zu bytes\n", payload_len);
    
    // Analyze for IEX trading messages
    analyze_iex_payload(udp_payload, payload_len);
}

int main() {
    // Open chunk file manually
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
    
    int packet_count = 0;
    
    // Analyze first few packets
    while (remaining > 8 && packet_count < 3) {
        uint32_t block_type = *((uint32_t *)data_ptr);
        block_len = *((uint32_t *)(data_ptr + 4));
        
        if (block_type == PCAPNG_EPB_TYPE && block_len >= sizeof(pcapng_epb_t)) {
            pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
            uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
            
            if (epb->captured_len > 100) {
                printf("\n\n>>> PACKET %d <<<\n", packet_count + 1);
                analyze_packet(packet_data, epb->captured_len);
                packet_count++;
            }
        }
        
        data_ptr += block_len;
        remaining -= block_len;
    }
    
    munmap(data, st.st_size);
    close(fd);
    return 0;
}

// Decode IEX ticker symbol (8 bytes, space-padded)
void decode_symbol(const uint8_t *symbol_data, char *output) {
    int len = 0;
    for (int i = 0; i < 8; i++) {
        if (symbol_data[i] != 0x20 && symbol_data[i] != 0x00) {  // not space or null
            output[len++] = symbol_data[i];
        }
    }
    output[len] = '\0';
}

// Convert IEX price format (little endian)
double decode_price(uint32_t price_raw) {
    return (double)price_raw / 10000.0;  // IEX prices in 1/10000ths
}

// Decode IEX Trade Report message
void decode_trade_message(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x54) return;  // Not a trade message
    
    const uint8_t *msg = &data[offset];
    uint64_t timestamp = *(uint64_t*)(msg + 1);  // 8-byte timestamp
    const uint8_t *symbol = msg + 9;              // Symbol at offset 9
    uint32_t price = *(uint32_t*)(msg + 17);      // Price at offset 17
    uint32_t size = *(uint32_t*)(msg + 21);       // Size at offset 21
    uint8_t side = msg[25];                       // Side at offset 25
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    printf("TRADE: %-8s  $%-8.4f  %8u shares  %c  (ts:%llu)\n",
           ticker, decode_price(price), size, side, timestamp);
}

// Decode IEX Quote Update message  
void decode_quote_message(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x51) return;  // Not a quote message
    
    const uint8_t *msg = &data[offset];
    uint64_t timestamp = *(uint64_t*)(msg + 1);
    const uint8_t *symbol = msg + 9;
    uint32_t bid_price = *(uint32_t*)(msg + 17);
    uint32_t bid_size = *(uint32_t*)(msg + 21);
    uint32_t ask_price = *(uint32_t*)(msg + 25);
    uint32_t ask_size = *(uint32_t*)(msg + 29);
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    printf("QUOTE: %-8s  Bid:$%-8.4f x%-6u  Ask:$%-8.4f x%-6u  (ts:%llu)\n",
           ticker, decode_price(bid_price), bid_size, 
           decode_price(ask_price), ask_size, timestamp);
}

// Analyze UDP payload for IEX messages
void analyze_iex_payload(const uint8_t *udp_payload, size_t len) {
    printf("\n=== IEX Message Analysis ===\n");
    
    int message_count = 0;
    
    // Look for message patterns - they seem to start after timestamp patterns
    for (size_t i = 0; i < len - 30; i++) {
        uint8_t msg_type = udp_payload[i];
        
        // Check for Trade Report (0x54)
        if (msg_type == 0x54 && i + 26 < len) {
            // Verify this looks like a real message by checking symbol area
            const uint8_t *symbol_area = &udp_payload[i + 9];
            if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                decode_trade_message(udp_payload, i);
                message_count++;
                if (message_count >= 10) break;  // Limit output
            }
        }
        
        // Check for Quote Update (0x51)
        else if (msg_type == 0x51 && i + 33 < len) {
            const uint8_t *symbol_area = &udp_payload[i + 9];
            if (symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                decode_quote_message(udp_payload, i);
                message_count++;
                if (message_count >= 10) break;
            }
        }
    }
    
    printf("Found %d decodable messages\n", message_count);
}