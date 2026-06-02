#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../utils/gpu_info.cuh"
#include "../utils/timer.hpp"
#include "gift.cuh"

#define BUFFER_SIZE (8 * 1024 * 1024)
#define NUM_STREAMS 4
#define GIFT128_BLOCK_BYTES 16

__device__ __forceinline__ void store_xor_be128(uint8_t* out, const uint8_t* in, Gift128Block ks) {
    out[0]  = ((ks.hi >> 56) & 0xFF) ^ in[0];
    out[1]  = ((ks.hi >> 48) & 0xFF) ^ in[1];
    out[2]  = ((ks.hi >> 40) & 0xFF) ^ in[2];
    out[3]  = ((ks.hi >> 32) & 0xFF) ^ in[3];
    out[4]  = ((ks.hi >> 24) & 0xFF) ^ in[4];
    out[5]  = ((ks.hi >> 16) & 0xFF) ^ in[5];
    out[6]  = ((ks.hi >> 8) & 0xFF) ^ in[6];
    out[7]  = ((ks.hi >> 0) & 0xFF) ^ in[7];
    out[8]  = ((ks.lo >> 56) & 0xFF) ^ in[8];
    out[9]  = ((ks.lo >> 48) & 0xFF) ^ in[9];
    out[10] = ((ks.lo >> 40) & 0xFF) ^ in[10];
    out[11] = ((ks.lo >> 32) & 0xFF) ^ in[11];
    out[12] = ((ks.lo >> 24) & 0xFF) ^ in[12];
    out[13] = ((ks.lo >> 16) & 0xFF) ^ in[13];
    out[14] = ((ks.lo >> 8) & 0xFF) ^ in[14];
    out[15] = ((ks.lo >> 0) & 0xFF) ^ in[15];
}

__global__ void encryptCTRKernel(const uint8_t* plaintext, uint8_t* ciphertext, size_t length, Gift128Block counter) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    int lane = threadIdx.x & 31;
    int warp_global = tid >> 5;

    size_t block_idx = (size_t)warp_global * 32 + lane;
    size_t byte_idx = block_idx * GIFT128_BLOCK_BYTES;

    bool active = byte_idx < length;
    unsigned mask = __ballot_sync(FULL_MASK, active);
    if (mask == 0) return;

    Gift128Block ctr;
    ctr.lo = counter.lo + (uint64_t)block_idx;
    ctr.hi = counter.hi + (ctr.lo < counter.lo ? 1ull : 0ull);

    Gift128Block ks = gift128_encrypt_bl(ctr, mask);
    
    if (active)
        store_xor_be128(ciphertext + byte_idx, plaintext + byte_idx, ks);
}

static void hex_to_key(const char* hex_str, uint16_t* key) {
    uint8_t key_bytes[16] = {0};

    for (int i = 0; i < 16; i++)
        sscanf(hex_str + 2*i, "%2hhx", &key_bytes[i]);

    for (int i = 0; i < 8; i++) {
        key[7 - i] = ((uint16_t)key_bytes[2*i] << 8) |
                     ((uint16_t)key_bytes[2*i + 1]);
    }
}

static void hex_to_iv(const char* hex_str, Gift128Block* iv) {
    uint8_t iv_bytes[16] = {0};

    for (int i = 0; i < 16; i++)
        sscanf(hex_str + 2*i, "%2hhx", &iv_bytes[i]);

    iv->hi = ((uint64_t)iv_bytes[0] << 56) |
             ((uint64_t)iv_bytes[1] << 48) |
             ((uint64_t)iv_bytes[2] << 40) |
             ((uint64_t)iv_bytes[3] << 32) |
             ((uint64_t)iv_bytes[4] << 24) |
             ((uint64_t)iv_bytes[5] << 16) |
             ((uint64_t)iv_bytes[6] <<  8) |
             ((uint64_t)iv_bytes[7] <<  0);

    iv->lo = ((uint64_t)iv_bytes[8]  << 56) |
             ((uint64_t)iv_bytes[9]  << 48) |
             ((uint64_t)iv_bytes[10] << 40) |
             ((uint64_t)iv_bytes[11] << 32) |
             ((uint64_t)iv_bytes[12] << 24) |
             ((uint64_t)iv_bytes[13] << 16) |
             ((uint64_t)iv_bytes[14] <<  8) |
             ((uint64_t)iv_bytes[15] <<  0);
}

int main(int argc, char* argv[]) {
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "Usage: %s -e|-d <input_file> <key> <iv> <output_file> [--nopad]\n", argv[0]);
        return 1;
    }

    int no_pad = (argc == 7 && strcmp(argv[6], "--nopad") == 0) ? 1 : 0;

    if (!gpuIsAvailable()) {
        fprintf(stderr, "No CUDA devices found.\n");
        return 1;
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

    uint16_t key[8];
    hex_to_key(argv[3], key);
    init_gift128_round_keys_device(key);


    Gift128Block iv;
    hex_to_iv(argv[4], &iv);

    FILE* output_file = fopen(argv[5], "wb");
    if (!output_file) { 
        perror("Failed to open output file"); 
        fclose(input_file); 
        return 1; 
    }

    // Pinned host buffers
    uint8_t* h_in;
    uint8_t* h_out;
    cudaMallocHost(&h_in,  BUFFER_SIZE + GIFT128_BLOCK_BYTES);
    cudaMallocHost(&h_out, BUFFER_SIZE + GIFT128_BLOCK_BYTES);

    // Device buffers and key
    uint8_t* d_in;
    uint8_t* d_out;

    cudaMalloc(&d_in,  BUFFER_SIZE + GIFT128_BLOCK_BYTES);
    cudaMalloc(&d_out, BUFFER_SIZE + GIFT128_BLOCK_BYTES);

    cudaStream_t streams[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++)
        cudaStreamCreate(&streams[i]);

    Timer t;
    t.start();

    Gift128Block counter = iv;
    size_t total_processed = 0;

    while (total_processed < total_size) {
        size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);

        size_t bytes_read = fread(h_in, 1, to_read, input_file);
        if (bytes_read == 0) break;

        size_t process_size = bytes_read;
        bool is_last = (total_processed + bytes_read >= total_size);

        if (strcmp(argv[1], "-e") == 0 && is_last) {
            size_t pad_len = GIFT128_BLOCK_BYTES - (bytes_read % GIFT128_BLOCK_BYTES);
            if (pad_len == 0) pad_len = GIFT128_BLOCK_BYTES;
            memset(h_in + bytes_read, (uint8_t)pad_len, pad_len);
            process_size = bytes_read + pad_len;
        }

        size_t chunk_size = (process_size / NUM_STREAMS) & ~(size_t)(GIFT128_BLOCK_BYTES - 1);

        for (int s = 0; s < NUM_STREAMS; s++) {
            size_t offset = s * chunk_size;
            size_t current_chunk_size = (s == NUM_STREAMS - 1) ? (process_size - offset) : chunk_size;
            if (current_chunk_size <= 0) continue;
            Gift128Block stream_counter = counter;
            uint64_t add_blocks = offset / GIFT128_BLOCK_BYTES;
            stream_counter.lo += add_blocks;
            if (stream_counter.lo < counter.lo)
                stream_counter.hi++;

            int num_blocks_per_chunk = current_chunk_size / GIFT128_BLOCK_BYTES;
            int warps = (num_blocks_per_chunk + 31) / 32;
            int threads = 256;
            int blocks = (warps * 32 + threads - 1) / threads;
            if (blocks == 0) blocks = 1;

            cudaMemcpyAsync(d_in + offset, h_in + offset, current_chunk_size, cudaMemcpyHostToDevice, streams[s]);
            encryptCTRKernel<<<blocks, threads, 0, streams[s]>>>(d_in + offset, d_out + offset, current_chunk_size, stream_counter);
            cudaMemcpyAsync(h_out + offset, d_out + offset, current_chunk_size, cudaMemcpyDeviceToHost, streams[s]);
        }
        cudaDeviceSynchronize();

        size_t write_size = process_size;
        if (strcmp(argv[1], "-d") == 0 && is_last) {
            uint8_t pad_len = h_out[process_size - 1];
            write_size = process_size - pad_len;
        }

        fwrite(h_out, 1, write_size, output_file);
        total_processed += bytes_read;
        uint64_t blocks_used = process_size / GIFT128_BLOCK_BYTES;
        uint64_t old_lo = counter.lo;
        counter.lo += blocks_used;
        if (counter.lo < old_lo)
            counter.hi++;
    }

    for (int i = 0; i < NUM_STREAMS; i++)
        cudaStreamDestroy(streams[i]);

    cudaFree(d_in);
    cudaFree(d_out);

    cudaFreeHost(h_in);
    cudaFreeHost(h_out);

    fclose(input_file);
    fclose(output_file);

    return 0;
}