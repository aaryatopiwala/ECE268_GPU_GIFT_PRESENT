// Cipher Block Chaining (CBC) with AES-128
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include "../utils/gpu_info.cuh"
#include "../utils/timer.hpp"
#include "aes.cuh"

#define BUFFER_SIZE (8 * 1024 * 1024)
#define NUM_STREAMS 4

__global__ void encryptCBCKernel(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const uint64_t *key, uint64_t counter_hi, uint64_t counter_lo) {
    
}

__global__ void decryptCBCKernel(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const uint64_t *key, uint64_t counter_hi, uint64_t counter_lo) {
    
}

static uint64_t last_block_as_u64(const uint8_t* buf, size_t len) {
    size_t base = len - 8;
    return ((uint64_t)buf[base]   << 56) | ((uint64_t)buf[base+1] << 48) |
           ((uint64_t)buf[base+2] << 40) | ((uint64_t)buf[base+3] << 32) |
           ((uint64_t)buf[base+4] << 24) | ((uint64_t)buf[base+5] << 16) |
           ((uint64_t)buf[base+6] <<  8) | ((uint64_t)buf[base+7]);
}

void hex_to_key(const char *hex_str, uint64_t *key) {
    uint64_t hex_len = strlen(hex_str);
    uint8_t key_bytes[16] = {0};
    for (int i = 0; i < 16 && 2*i < (int)hex_len; i++)
        sscanf(hex_str + 2*i, "%2hhx", &key_bytes[i]);
    key[0] = ((uint64_t)key_bytes[0] << 56) | ((uint64_t)key_bytes[1] << 48) |
             ((uint64_t)key_bytes[2] << 40) | ((uint64_t)key_bytes[3] << 32) |
             ((uint64_t)key_bytes[4] << 24) | ((uint64_t)key_bytes[5] << 16) |
             ((uint64_t)key_bytes[6] <<  8) | ((uint64_t)key_bytes[7]);
    key[1] = ((uint64_t)key_bytes[8]  << 56) | ((uint64_t)key_bytes[9]  << 48) |
             ((uint64_t)key_bytes[10] << 40) | ((uint64_t)key_bytes[11] << 32) |
             ((uint64_t)key_bytes[12] << 24) | ((uint64_t)key_bytes[13] << 16) |
             ((uint64_t)key_bytes[14] <<  8) | ((uint64_t)key_bytes[15]);
}

int main(int argc, char *argv[]) {
    // -e for encryption, -d for decryption
    // key and iv are provided as hexadecimal strings
    // ./present_cbc -e plaintext.txt "key" "iv" ciphertext.bin --nopad
    // ./present_cbc -d ciphertext.txt "key" "iv" decrypted.txt --nopad
    // --nopad for no padding, useful for test vectors.
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "Usage: %s -e|-d <input_file> <key> <iv> <output_file>\n", argv[0]);
        return 1;
    }
    int no_pad = (argc == 7 && strcmp(argv[6], "--nopad") == 0) ? 1 : 0;

    if (!gpuIsAvailable()) { 
        fprintf(stderr, "No CUDA devices found.\n"); return 1; 
    }
    gpuPrintProperties();
    gpuSelectBestDevice();

    FILE *input_file = fopen(argv[2], "rb");
    if (!input_file) {
        perror("Failed to open input file");
        return 1;
    }
    fseek(input_file, 0, SEEK_END);
    size_t total_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    uint64_t key[2] = {0, 0};
    hex_to_key(argv[3], key);
    uint64_t iv[2] = {0, 0};
    hex_to_key(argv[4], iv);

    FILE *output_file = fopen(argv[5], "wb");
    if (!output_file) {
        perror("Failed to open output file");
        fclose(input_file);
        return 1;
    }

    // Pinned host buffers
    uint8_t* h_in;
    uint8_t* h_out;
    cudaMallocHost(&h_in,  BUFFER_SIZE + 16);
    cudaMallocHost(&h_out, BUFFER_SIZE + 16);

    // Device buffers and key
    uint8_t*  d_in;
    uint8_t*  d_out;
    uint64_t* d_key;
    cudaMalloc(&d_in,  BUFFER_SIZE + 16);
    cudaMalloc(&d_out, BUFFER_SIZE + 16);
    cudaMalloc(&d_key, 2 * sizeof(uint64_t));
    cudaMemcpy(d_key, key, 2 * sizeof(uint64_t), cudaMemcpyHostToDevice);

    cudaStream_t streams[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++)
        cudaStreamCreate(&streams[i]);

    Timer t;
    t.start();
    
    if (strcmp(argv[1], "-e") == 0) {
        size_t total_processed = 0;
        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(h_in, 1, to_read, input_file);
            if (bytes_read == 0) break;

            size_t process_size = bytes_read;
            bool is_last = (total_processed + bytes_read >= total_size);

            if (is_last && !no_pad) {
                size_t pad_len = 16 - (bytes_read % 16);
                memset(h_in + bytes_read, pad_len, pad_len);
                process_size = bytes_read + pad_len;
            }

            uint64_t buf_ctr_lo = iv[1] + (total_processed / 16);
            uint64_t buf_ctr_hi = iv[0] + (buf_ctr_lo < iv[1] ? 1ULL : 0ULL);
            int chunk_size = (int)(process_size / NUM_STREAMS) & ~15;
            for (int s = 0; s < NUM_STREAMS; s++) {
                int offset = s * chunk_size;
                int current_chunk_size = (s == NUM_STREAMS-1) ? (process_size - offset) : chunk_size;
                if (current_chunk_size <= 0) continue;
                uint64_t stream_ctr_lo = buf_ctr_lo + (uint64_t)(offset / 16);
                uint64_t stream_ctr_hi = buf_ctr_hi + (stream_ctr_lo < buf_ctr_lo ? 1ULL : 0ULL);
                int num_blocks = current_chunk_size / 16;
                int threads    = 256;
                int blocks     = (num_blocks + threads - 1) / threads;
                if (blocks == 0) blocks = 1;
                cudaMemcpyAsync(d_in  + offset, h_in + offset, current_chunk_size, cudaMemcpyHostToDevice, streams[s]);
                encryptCBCKernel<<<blocks, threads, 0, streams[s]>>>(d_in + offset, d_out + offset, current_chunk_size, d_key, stream_ctr_hi, stream_ctr_lo);
                cudaMemcpyAsync(h_out + offset, d_out + offset, current_chunk_size, cudaMemcpyDeviceToHost, streams[s]);
            }
            cudaDeviceSynchronize();
            
            prev_cipher = last_block_as_u64(h_out, process_size);
            fwrite(h_out, 1, process_size, output_file);
            total_processed += bytes_read;
        }
    }
    else if (strcmp(argv[1], "-d") == 0) {
        size_t total_processed = 0;
        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(h_in, 1, to_read, input_file);
            if (bytes_read == 0) break;

            size_t process_size = bytes_read;
            bool is_last = (total_processed + bytes_read >= total_size);

            uint64_t buf_ctr_lo = iv[1] + (total_processed / 16);
            uint64_t buf_ctr_hi = iv[0] + (buf_ctr_lo < iv[1] ? 1ULL : 0ULL);
            int chunk_size = (int)(process_size / NUM_STREAMS) & ~15;
            for (int s = 0; s < NUM_STREAMS; s++) {
                int offset = s * chunk_size;
                int current_chunk_size = (s == NUM_STREAMS-1) ? (process_size - offset) : chunk_size;
                if (current_chunk_size <= 0) continue;
                uint64_t stream_ctr_lo = buf_ctr_lo + (uint64_t)(offset / 16);
                uint64_t stream_ctr_hi = buf_ctr_hi + (stream_ctr_lo < buf_ctr_lo ? 1ULL : 0ULL);
                int num_blocks = current_chunk_size / 16;
                int threads    = 256;
                int blocks     = (num_blocks + threads - 1) / threads;
                if (blocks == 0) blocks = 1;
                cudaMemcpyAsync(d_in  + offset, h_in + offset, current_chunk_size, cudaMemcpyHostToDevice, streams[s]);
                decryptCBCKernel<<<blocks, threads, 0, streams[s]>>>(d_in + offset, d_out + offset, current_chunk_size, d_key, stream_ctr_hi, stream_ctr_lo);
                cudaMemcpyAsync(h_out + offset, d_out + offset, current_chunk_size, cudaMemcpyDeviceToHost, streams[s]);
            }
            cudaDeviceSynchronize();
            size_t write_size = process_size;

            if (is_last && !no_pad) {
                uint8_t pad_len = h_out[bytes_read - 1];
                if (pad_len > 0 && pad_len <= 16) {
                    write_size = bytes_read - pad_len;
                } else if (pad_len == 0) {
                    write_size = bytes_read - 16;
                }
            }
            
            fwrite(h_out, 1, write_size, output_file);
            total_processed += bytes_read;
        }
    }
    else {
        fprintf(stderr, "Invalid option: %s\n", argv[1]);
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    fprintf(stdout, "[timer] total: %ld ms\n", t.stopMs());

    for (int i = 0; i < NUM_STREAMS; i++) cudaStreamDestroy(streams[i]);
    cudaFree(d_in);
    cudaFree(d_out);
    cudaFree(d_key);
    cudaFreeHost(h_in);
    cudaFreeHost(h_out);
    fclose(input_file);
    fclose(output_file);
    return 0;
}