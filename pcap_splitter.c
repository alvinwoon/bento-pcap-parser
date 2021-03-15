#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define PCAPNG_MAGIC 0x0a0d0d0a
#define PCAPNG_EPB_TYPE 0x00000006
#define PCAPNG_IDB_TYPE 0x00000001

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input.pcap> <size_mb>\n", argv[0]);
        printf("Splits pcapng file into smaller files of specified size\n");
        return 1;
    }
    
    const char *input_file = argv[1];
    int size_mb = atoi(argv[2]);
    size_t target_size = size_mb * 1024 * 1024;
    
    // Open and map input file
    int fd = open(input_file, O_RDONLY);
    if (fd == -1) {
        perror("open input file");
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
    
    printf("Input file: %s (%zu bytes)\n", input_file, st.st_size);
    printf("Target chunk size: %d MB (%zu bytes)\n", size_mb, target_size);
    
    // Verify it's pcapng
    uint32_t magic = *((uint32_t *)data);
    if (magic != PCAPNG_MAGIC) {
        fprintf(stderr, "Not a pcapng file\n");
        munmap(data, st.st_size);
        close(fd);
        return 1;
    }
    
    uint8_t *ptr = data;
    size_t remaining = st.st_size;
    int file_num = 1;
    size_t shb_size = 0;
    uint8_t *shb_data = NULL;
    
    // Read Section Header Block first
    if (remaining >= 8) {
        uint32_t block_len = *((uint32_t *)(ptr + 4));
        shb_size = block_len;
        shb_data = ptr;
        ptr += block_len;
        remaining -= block_len;
        printf("Section Header Block: %zu bytes\n", shb_size);
    }
    
    while (remaining > 0) {
        char output_name[256];
        snprintf(output_name, sizeof(output_name), "chunk_%02d.pcap", file_num);
        
        FILE *out = fopen(output_name, "wb");
        if (!out) {
            perror("fopen output");
            break;
        }
        
        // Write Section Header Block to each output file
        fwrite(shb_data, 1, shb_size, out);
        size_t written = shb_size;
        
        printf("Creating %s...", output_name);
        fflush(stdout);
        
        // Copy blocks until we reach target size
        while (remaining >= 8 && written < target_size) {
            uint32_t block_type = *((uint32_t *)ptr);
            uint32_t block_len = *((uint32_t *)(ptr + 4));
            
            if (block_len < 12 || block_len > remaining) {
                fprintf(stderr, "Invalid block length: %u\n", block_len);
                break;
            }
            
            // Write the entire block
            fwrite(ptr, 1, block_len, out);
            written += block_len;
            ptr += block_len;
            remaining -= block_len;
            
            // Stop at Enhanced Packet Blocks to keep packet boundaries
            if (block_type == PCAPNG_EPB_TYPE && written >= target_size * 0.8) {
                break;
            }
        }
        
        fclose(out);
        printf(" %zu bytes written\n", written);
        
        file_num++;
        
        // Stop if we've processed enough or if remaining is small
        if (remaining < 1024 * 1024) { // Less than 1MB left
            printf("Remaining data too small (%zu bytes), stopping\n", remaining);
            break;
        }
    }
    
    munmap(data, st.st_size);
    close(fd);
    
    printf("Split complete! Created %d files\n", file_num - 1);
    return 0;
}