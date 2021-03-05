#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "pcap.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s <pcap_file>\n", prog_name);
    printf("High-performance IEX PCAP parser for HFT systems\n");
}

double get_time_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_usec - start->tv_usec) / 1000000.0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    mmap_context_t ctx = {0};
    struct timeval start, end;
    
    printf("Initializing high-performance PCAP parser...\n");
    printf("Target file: %s\n", filename);
    
    gettimeofday(&start, NULL);
    
    // Initialize memory-mapped parser
    if (init_mmap_parser(filename, &ctx) != 0) {
        fprintf(stderr, "Failed to initialize parser\n");
        return 1;
    }
    
    printf("File mapped successfully, size: %zu bytes\n", ctx.size);
    
    // Parse the PCAP file
    int result = parse_pcap_file(&ctx);
    
    if (result != 0) {
        fprintf(stderr, "Parse failed with result: %d\n", result);
    }
    
    gettimeofday(&end, NULL);
    
    // Calculate throughput
    double elapsed = get_time_diff(&start, &end);
    double throughput_mbps = (ctx.size / (1024.0 * 1024.0)) / elapsed;
    
    printf("\nPerformance Results:\n");
    printf("File size: %.2f MB\n", ctx.size / (1024.0 * 1024.0));
    printf("Parse time: %.3f seconds\n", elapsed);
    printf("Throughput: %.2f MB/s\n", throughput_mbps);
    
    // Cleanup
    cleanup_mmap_parser(&ctx);
    
    return (result == 0) ? 0 : 1;
}