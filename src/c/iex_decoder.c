#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "iex.h"

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