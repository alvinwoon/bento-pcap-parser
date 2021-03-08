.text
.global _parse_pcap_chunk_asm
.global _validate_pcap_header_asm

// Parse PCAP chunk with NEON optimization
// x0 = data pointer, x1 = size, x2 = output pointer
_parse_pcap_chunk_asm:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    
    mov x19, x0        // data pointer
    mov x20, x1        // size
    mov x21, x2        // output pointer
    mov x22, #0        // packet counter
    
1:  // packet_loop
    cmp x20, #16       // minimum packet header size
    b.lt 3f            // done
    
    // Load packet header (16 bytes) using NEON
    ld1 {v0.16b}, [x19]
    
    // Extract caplen (bytes 8-11, little endian)
    mov w3, v0.s[2]
    
    // Validate packet size
    cmp w3, #65536
    b.hi 2f            // skip_packet
    cbz w3, 2f         // skip if zero
    
    // Check if we have enough data
    add w4, w3, #16    // header + data
    cmp x20, x4
    b.lt 3f            // done
    
    // Process packet data (call IEX parser)
    add x0, x19, #16   // skip pcap header
    mov x1, x3         // data size only
    mov x2, x21        // output
    bl _extract_iex_messages_asm
    
    // Update counters
    add x22, x22, #1   // increment packet count
    add w4, w3, #16    // total packet size
    add x19, x19, x4   // move to next packet
    sub x20, x20, x4   // decrease remaining
    b 1b               // packet_loop
    
2:  // skip_packet
    add w4, w3, #16
    add x19, x19, x4
    sub x20, x20, x4
    b 1b
    
3:  // done
    mov x0, x22        // return packet count
    
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

// Validate PCAP/PCAPNG header
// x0 = header pointer, returns 1 if valid, 0 if invalid
_validate_pcap_header_asm:
    ldr w1, [x0]       // load magic
    
    // Check for traditional PCAP magic
    movz w2, #0xc3d4   // PCAP magic constant (lower 16 bits)
    movk w2, #0xa1b2, lsl #16 // upper 16 bits
    cmp w1, w2
    b.eq 1f            // valid
    movz w2, #0xb2a1   // swapped endian (lower 16 bits)
    movk w2, #0xd4c3, lsl #16 // upper 16 bits
    cmp w1, w2
    b.eq 1f            // valid
    
    // Check for PCAPNG magic
    movz w2, #0x0d0a   // PCAPNG magic constant (lower 16 bits)
    movk w2, #0x0a0d, lsl #16 // upper 16 bits
    cmp w1, w2
    b.eq 1f            // valid
    
    mov x0, #0
    ret
1:  // valid
    mov x0, #1
    ret