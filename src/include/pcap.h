#ifndef PCAP_H
#define PCAP_H

#include <stdint.h>
#include <sys/mman.h>

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAPNG_MAGIC 0x0a0d0d0a
#define PCAP_CHUNK_SIZE (2 * 1024 * 1024)  // 2MB chunks
#define MAX_PACKET_SIZE 65536

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed)) pcap_header_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t byte_order_magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint64_t section_length;
} __attribute__((packed)) pcapng_shb_t;

#define PCAPNG_EPB_TYPE 0x00000006  // Enhanced Packet Block
#define PCAPNG_IDB_TYPE 0x00000001  // Interface Description Block

typedef struct {
    uint32_t block_type;     // 0x00000006
    uint32_t block_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    // packet data follows
} __attribute__((packed)) pcapng_epb_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
} __attribute__((packed)) pcap_record_header_t;

typedef struct {
    void *data;
    size_t size;
    size_t offset;
    int fd;
} mmap_context_t;

// Assembly function declarations
extern void parse_pcap_chunk_asm(const uint8_t *data, size_t size, void *output);
extern int validate_pcap_header_asm(const pcap_header_t *header);
extern uint32_t extract_iex_messages_asm(const uint8_t *packet_data, size_t len, void *output);

// C wrapper functions
int init_mmap_parser(const char *filename, mmap_context_t *ctx);
void cleanup_mmap_parser(mmap_context_t *ctx);
int parse_pcap_file(mmap_context_t *ctx);

#endif