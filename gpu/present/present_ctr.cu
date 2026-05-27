#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../utils/gpu_info.cuh"
#include "../utils/timer.hpp"
#include "present.cuh"

#define BUFFER_SIZE (8 * 1024 * 1024)
#define NUM_STREAMS 4

__global__ void encryptCTRKernel(const uint8_t* plaintext, uint8_t* ciphertext, size_t length, const uint64_t* key, uint64_t counter) {
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    size_t stride = blockDim.x * gridDim.x;
    for (size_t i = tid * 8; i < length; i += stride * 8) {
        uint64_t block = counter + (i / 8);
        uint64_t cipher_block;
        present80_encrypt(&block, key, &cipher_block);

        ciphertext[i] = ((cipher_block >> 56) & 0xFF) ^ plaintext[i];
        ciphertext[i+1] = ((cipher_block >> 48) & 0xFF) ^ plaintext[i+1];
        ciphertext[i+2] = ((cipher_block >> 40) & 0xFF) ^ plaintext[i+2];
        ciphertext[i+3] = ((cipher_block >> 32) & 0xFF) ^ plaintext[i+3];
        ciphertext[i+4] = ((cipher_block >> 24) & 0xFF) ^ plaintext[i+4];
        ciphertext[i+5] = ((cipher_block >> 16) & 0xFF) ^ plaintext[i+5];
        ciphertext[i+6] = ((cipher_block >> 8) & 0xFF) ^ plaintext[i+6];
        ciphertext[i+7] = ((cipher_block >> 0) & 0xFF) ^ plaintext[i+7];
    }
}

static void hex_to_key(const char* hex_str, uint64_t* key) {
    uint8_t key_bytes[10] = {0};
    for (int i = 0; i < 10; i++)
        sscanf(hex_str + 2*i, "%2hhx", &key_bytes[i]);
    key[0] = ((uint64_t)key_bytes[0] << 56) | ((uint64_t)key_bytes[1] << 48) |
             ((uint64_t)key_bytes[2] << 40) | ((uint64_t)key_bytes[3] << 32) |
             ((uint64_t)key_bytes[4] << 24) | ((uint64_t)key_bytes[5] << 16) |
             ((uint64_t)key_bytes[6] <<  8) |  (uint64_t)key_bytes[7];
    key[1] = ((uint64_t)key_bytes[8] << 8) | (uint64_t)key_bytes[9];
}

int main(int argc, char* argv[]) {
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "Usage: %s -e|-d <input_file> <key> <iv> <output_file> [--nopad]\n", argv[0]);
        return 1;
    }
    int no_pad = (argc == 7 && strcmp(argv[6], "--nopad") == 0) ? 1 : 0;

    if (!gpuIsAvailable()) { 
        fprintf(stderr, "No CUDA devices found.\n"); return 1; 
    }
    gpuPrintProperties();
    gpuSelectBestDevice();

    FILE* input_file = fopen(argv[2], "rb");
    if (!input_file) { 
        perror("Failed to open input file"); 
        return 1; 
    }
    fseek(input_file, 0, SEEK_END);
    size_t total_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    uint64_t key[2];
    hex_to_key(argv[3], key);
    uint64_t iv = (uint64_t)strtoull(argv[4], nullptr, 16);

    FILE* output_file = fopen(argv[5], "wb");
    if (!output_file) { 
        perror("Failed to open output file"); 
        fclose(input_file); 
        return 1; 
    }

    // Pinned host buffers
    uint8_t* h_in;
    uint8_t* h_out;
    cudaMallocHost(&h_in,  BUFFER_SIZE + 8);
    cudaMallocHost(&h_out, BUFFER_SIZE + 8);

    // Device buffers and key
    uint8_t*  d_in;
    uint8_t*  d_out;
    uint64_t* d_key;
    cudaMalloc(&d_in,  BUFFER_SIZE + 8);
    cudaMalloc(&d_out, BUFFER_SIZE + 8);
    cudaMalloc(&d_key, 2 * sizeof(uint64_t));
    cudaMemcpy(d_key, key, 2 * sizeof(uint64_t), cudaMemcpyHostToDevice);

    cudaStream_t streams[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++)
        cudaStreamCreate(&streams[i]);

    Timer t;
    t.start();

    uint64_t counter = iv;
    size_t total_processed = 0;

    while (total_processed < total_size) {
        size_t to_read    = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
        size_t bytes_read = fread(h_in, 1, to_read, input_file);
        if (bytes_read == 0) break;

        size_t process_size = bytes_read;
        bool is_last = (total_processed + bytes_read >= total_size);

        if (strcmp(argv[1], "-e") == 0 && is_last && !no_pad) {
            size_t pad_len = 8 - (bytes_read % 8);
            memset(h_in + bytes_read, (uint8_t)pad_len, pad_len);
            process_size = bytes_read + pad_len;
        }

        int chunk_size      = (int)(process_size / NUM_STREAMS) & ~7;

        for (int s = 0; s < NUM_STREAMS; s++) {
            int offset = s * chunk_size;
            int current_chunk_size = (s == NUM_STREAMS - 1) ? (process_size - offset) : chunk_size;
            if (current_chunk_size <= 0) continue;
            uint64_t stream_counter = counter + (uint64_t)(offset / 8);
            int num_blocks_per_chunk = current_chunk_size / 8;
            int threads = 256;
            int blocks  = (num_blocks_per_chunk + threads - 1) / threads;
            if (blocks == 0) blocks = 1;
            cudaMemcpyAsync(d_in + offset, h_in + offset, current_chunk_size, cudaMemcpyHostToDevice, streams[s]);
            encryptCTRKernel<<<blocks, threads, 0, streams[s]>>>(d_in + offset, d_out + offset, current_chunk_size, d_key, stream_counter);
            cudaMemcpyAsync(h_out + offset, d_out + offset, current_chunk_size, cudaMemcpyDeviceToHost, streams[s]);
        }
        cudaDeviceSynchronize();

        size_t write_size = process_size;
        if (strcmp(argv[1], "-d") == 0 && is_last && !no_pad) {
            uint8_t pad_len = h_out[process_size - 1];
            if (pad_len > 0 && pad_len <= 8)
                write_size = process_size - pad_len;
            else if (pad_len == 0)
                write_size = process_size - 8;
        }

        fwrite(h_out, 1, write_size, output_file);
        total_processed += bytes_read;
        counter += process_size / 8;
    }

    fprintf(stdout, "[timer] total: %ld ms\n", t.stopMs());

    for (int i = 0; i < NUM_STREAMS; i++) cudaStreamDestroy(streams[i]);
    cudaFree(d_in); cudaFree(d_out); cudaFree(d_key);
    cudaFreeHost(h_in); cudaFreeHost(h_out);
    fclose(input_file);
    fclose(output_file);
    return 0;
}
