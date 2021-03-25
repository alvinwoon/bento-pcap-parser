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

// IEX Message types from their specification
const char* get_iex_message_type(uint8_t type) {
    switch(type) {
        case 0x53: return "System Event";
        case 0x44: return "Security Directory";
        case 0x48: return "Trading Status";
        case 0x4F: return "Operational Halt";
        case 0x50: return "Short Sale Price Test Status";
        case 0x51: return "Quote Update";
        case 0x54: return "Trade Report";
        case 0x58: return "Official Price";
        case 0x42: return "Trade Break";
        case 0x41: return "Auction Information";
        case 0x52: return "Retail Interest Indicator";
        default: return "Unknown";
    }
}

void decode_symbol(const uint8_t *symbol_data, char *output) {
    int len = 0;
    for (int i = 0; i < 8; i++) {
        if (symbol_data[i] != 0x20 && symbol_data[i] != 0x00) {
            output[len++] = symbol_data[i];
        }
    }
    output[len] = '\0';
}

void analyze_security_directory(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x44) return;
    
    const uint8_t *msg = &data[offset];
    const uint8_t *symbol = msg + 9;
    uint8_t round_lot_size = msg[17];
    uint8_t adjusted_poc_price = msg[18];
    uint8_t luld_tier = msg[19];
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    printf("SECURITY: %-8s  RoundLot:%u  LULDTier:%c\n",
           ticker, round_lot_size, luld_tier);
}

void analyze_trading_status(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x48) return;
    
    const uint8_t *msg = &data[offset];
    const uint8_t *symbol = msg + 9;
    uint8_t trading_status = msg[17];
    uint8_t reason = msg[18];
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    const char* status_desc = "";
    switch(trading_status) {
        case 'H': status_desc = "Halted"; break;
        case 'O': status_desc = "Order Acceptance Period"; break;
        case 'P': status_desc = "Paused"; break;
        case 'T': status_desc = "Trading"; break;
        default: status_desc = "Unknown"; break;
    }
    
    printf("STATUS:   %-8s  %s  (Reason:%c)\n", ticker, status_desc, reason);
}

void analyze_quote_update(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x51) return;
    
    const uint8_t *msg = &data[offset];
    const uint8_t *symbol = msg + 9;
    uint32_t bid_price = *(uint32_t*)(msg + 17);
    uint32_t bid_size = *(uint32_t*)(msg + 21);
    uint32_t ask_price = *(uint32_t*)(msg + 25);
    uint32_t ask_size = *(uint32_t*)(msg + 29);
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    printf("QUOTE:    %-8s  Bid:$%-8.4f(%u)  Ask:$%-8.4f(%u)\n",
           ticker, (double)bid_price / 10000.0, bid_size,
           (double)ask_price / 10000.0, ask_size);
}

void analyze_auction_info(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x41) return;
    
    const uint8_t *msg = &data[offset];
    const uint8_t *symbol = msg + 9;
    uint8_t auction_type = msg[17];
    uint32_t paired_shares = *(uint32_t*)(msg + 18);
    uint32_t reference_price = *(uint32_t*)(msg + 22);
    
    char ticker[16];
    decode_symbol(symbol, ticker);
    
    const char* auction_desc = "";
    switch(auction_type) {
        case 'O': auction_desc = "Opening"; break;
        case 'C': auction_desc = "Closing"; break;
        case 'H': auction_desc = "IPO/Halt"; break;
        case 'I': auction_desc = "Intraday"; break;
        default: auction_desc = "Unknown"; break;
    }
    
    printf("AUCTION:  %-8s  %s  Paired:%u  RefPrice:$%.4f\n",
           ticker, auction_desc, paired_shares, (double)reference_price / 10000.0);
}

void analyze_system_event(const uint8_t *data, size_t offset) {
    if (data[offset] != 0x53) return;
    
    const uint8_t *msg = &data[offset];
    uint8_t system_event = msg[9];
    
    const char* event_desc = "";
    switch(system_event) {
        case 'O': event_desc = "Start of Messages"; break;
        case 'S': event_desc = "Start of System Hours"; break;
        case 'Q': event_desc = "Start of Market Hours"; break;
        case 'M': event_desc = "End of Market Hours"; break;
        case 'E': event_desc = "End of System Hours"; break;
        case 'C': event_desc = "End of Messages"; break;
        default: event_desc = "Unknown System Event"; break;
    }
    
    printf("SYSTEM:   %s (%c)\n", event_desc, system_event);
}

void comprehensive_message_analysis(const uint8_t *udp_payload, size_t len) {
    printf("\n=== Comprehensive IEX Message Analysis ===\n");
    
    // Count message types
    int message_counts[256] = {0};
    int total_messages = 0;
    
    for (size_t i = 0; i < len - 30; i++) {
        uint8_t msg_type = udp_payload[i];
        
        // Look for valid IEX message types
        if (msg_type >= 0x41 && msg_type <= 0x58) {
            const uint8_t *symbol_area = &udp_payload[i + 9];
            if (i + 30 < len && symbol_area[0] >= 'A' && symbol_area[0] <= 'Z') {
                message_counts[msg_type]++;
                total_messages++;
                
                // Analyze first few of each type
                if (message_counts[msg_type] <= 3) {
                    switch(msg_type) {
                        case 0x44: analyze_security_directory(udp_payload, i); break;
                        case 0x48: analyze_trading_status(udp_payload, i); break;
                        case 0x51: analyze_quote_update(udp_payload, i); break;
                        case 0x54: 
                            {
                                const uint8_t *msg = &udp_payload[i];
                                const uint8_t *symbol = msg + 9;
                                uint32_t price = *(uint32_t*)(msg + 17);
                                uint32_t size = *(uint32_t*)(msg + 21);
                                uint8_t side = msg[25];
                                
                                char ticker[16];
                                decode_symbol(symbol, ticker);
                                
                                printf("TRADE:    %-8s  $%-8.4f  %8u shares  %c\n",
                                       ticker, (double)price / 10000.0, size, 
                                       (side >= 32 && side <= 126) ? side : '?');
                            }
                            break;
                        case 0x41: analyze_auction_info(udp_payload, i); break;
                        case 0x53: analyze_system_event(udp_payload, i); break;
                        case 0x58:
                            {
                                const uint8_t *msg = &udp_payload[i];
                                const uint8_t *symbol = msg + 9;
                                uint32_t official_price = *(uint32_t*)(msg + 17);
                                
                                char ticker[16];
                                decode_symbol(symbol, ticker);
                                
                                printf("OFFICIAL: %-8s  $%-8.4f\n",
                                       ticker, (double)official_price / 10000.0);
                            }
                            break;
                    }
                }
            }
        }
    }
    
    printf("\n=== Message Type Summary ===\n");
    for (int i = 0; i < 256; i++) {
        if (message_counts[i] > 0) {
            printf("%s (0x%02X): %d messages\n", 
                   get_iex_message_type(i), i, message_counts[i]);
        }
    }
    printf("Total messages analyzed: %d\n", total_messages);
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
    
    int packet_count = 0;
    
    // Analyze large packets
    while (remaining > 8 && packet_count < 2) {
        uint32_t block_type = *((uint32_t *)data_ptr);
        block_len = *((uint32_t *)(data_ptr + 4));
        
        if (block_type == PCAPNG_EPB_TYPE && block_len >= sizeof(pcapng_epb_t)) {
            pcapng_epb_t *epb = (pcapng_epb_t *)data_ptr;
            uint8_t *packet_data = data_ptr + sizeof(pcapng_epb_t);
            
            if (epb->captured_len > 1000) {
                printf("\n\n>>> ANALYZING PACKET %d (%u bytes) <<<\n", 
                       packet_count + 1, epb->captured_len);
                
                const uint8_t *udp_payload = packet_data + 42;
                size_t payload_len = epb->captured_len - 42;
                
                comprehensive_message_analysis(udp_payload, payload_len);
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