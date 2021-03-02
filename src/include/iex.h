#ifndef IEX_H
#define IEX_H

#include <stdint.h>

// IEX message types
#define IEX_SYSTEM_EVENT        0x53
#define IEX_SECURITY_DIRECTORY  0x44
#define IEX_TRADING_STATUS      0x48
#define IEX_OPERATIONAL_HALT    0x4F
#define IEX_SHORT_SALE_PRICE    0x50
#define IEX_QUOTE_UPDATE        0x51
#define IEX_TRADE_REPORT        0x54
#define IEX_OFFICIAL_PRICE      0x58
#define IEX_TRADE_BREAK         0x42
#define IEX_AUCTION_INFO        0x41

typedef struct {
    uint8_t  message_type;
    uint32_t timestamp;
    uint64_t symbol;  // 8-byte symbol (padded)
} __attribute__((packed)) iex_message_header_t;

typedef struct {
    iex_message_header_t header;
    uint32_t bid_price;
    uint32_t bid_size;
    uint32_t ask_price;
    uint32_t ask_size;
} __attribute__((packed)) iex_quote_update_t;

typedef struct {
    iex_message_header_t header;
    uint32_t price;
    uint32_t size;
    uint8_t  side;  // 'B' or 'S'
} __attribute__((packed)) iex_trade_report_t;

// High-performance output structures
typedef struct {
    uint64_t timestamp_ns;
    uint64_t symbol_hash;
    uint32_t price;
    uint32_t size;
    uint8_t  message_type;
    uint8_t  side;
} __attribute__((packed)) parsed_message_t;

#define MAX_MESSAGES_PER_CHUNK 100000

typedef struct {
    parsed_message_t messages[MAX_MESSAGES_PER_CHUNK];
    uint32_t count;
    uint64_t total_processed;
} message_batch_t;

// Assembly parsing functions
extern void parse_iex_quote_asm(const uint8_t *data, parsed_message_t *output);
extern void parse_iex_trade_asm(const uint8_t *data, parsed_message_t *output);
extern uint64_t hash_symbol_asm(const uint8_t *symbol);

#endif