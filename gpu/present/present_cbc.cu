#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../utils/gpu_info.cuh"
#include "../utils/timer.hpp"
#include "present.cuh"

#define BUFFER_SIZE (8 * 1024 * 1024)
#define NUM_STREAMS 4

__global__ void encryptCBCKernel(const uint8_t* plaintext, uint8_t* ciphertext,
                                  int n, const uint64_t* key, uint64_t iv) {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    uint64_t prev_cipher = iv;
    for (int i = 0; i < n; i += 8) {
        uint64_t block = ((uint64_t)plaintext[i]   << 56) | ((uint64_t)plaintext[i+1] << 48) |
                         ((uint64_t)plaintext[i+2] << 40) | ((uint64_t)plaintext[i+3] << 32) |
                         ((uint64_t)plaintext[i+4] << 24) | ((uint64_t)plaintext[i+5] << 16) |
                         ((uint64_t)plaintext[i+6] <<  8) |  (uint64_t)plaintext[i+7];
        block ^= prev_cipher;
        uint64_t cipher_block;
        present80_encrypt(&block, key, &cipher_block);
        ciphertext[i]   = (cipher_block >> 56) & 0xFF;
        ciphertext[i+1] = (cipher_block >> 48) & 0xFF;
        ciphertext[i+2] = (cipher_block >> 40) & 0xFF;
        ciphertext[i+3] = (cipher_block >> 32) & 0xFF;
        ciphertext[i+4] = (cipher_block >> 24) & 0xFF;
        ciphertext[i+5] = (cipher_block >> 16) & 0xFF;
        ciphertext[i+6] = (cipher_block >>  8) & 0xFF;
        ciphertext[i+7] =  cipher_block & 0xFF;
        prev_cipher = cipher_block;
    }
}

__global__ void decryptCBCKernel(const uint8_t* ciphertext, uint8_t* plaintext,
                                  int n, const uint64_t* key, uint64_t iv) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int i   = idx * 8;
    if (i >= n) return;

    uint64_t cipher_block = ((uint64_t)ciphertext[i]   << 56) | ((uint64_t)ciphertext[i+1] << 48) |
                            ((uint64_t)ciphertext[i+2] << 40) | ((uint64_t)ciphertext[i+3] << 32) |
                            ((uint64_t)ciphertext[i+4] << 24) | ((uint64_t)ciphertext[i+5] << 16) |
                            ((uint64_t)ciphertext[i+6] <<  8) |  (uint64_t)ciphertext[i+7];
    uint64_t prev = (i == 0) ? iv
                              : (((uint64_t)ciphertext[i-8] << 56) | ((uint64_t)ciphertext[i-7] << 48) |
                                 ((uint64_t)ciphertext[i-6] << 40) | ((uint64_t)ciphertext[i-5] << 32) |
                                 ((uint64_t)ciphertext[i-4] << 24) | ((uint64_t)ciphertext[i-3] << 16) |
                                 ((uint64_t)ciphertext[i-2] <<  8) |  (uint64_t)ciphertext[i-1]);
    uint64_t block;
    present80_decrypt(&cipher_block, key, &block);
    block ^= prev;

    plaintext[i]   = (block >> 56) & 0xFF;
    plaintext[i+1] = (block >> 48) & 0xFF;
    plaintext[i+2] = (block >> 40) & 0xFF;
    plaintext[i+3] = (block >> 32) & 0xFF;
    plaintext[i+4] = (block >> 24) & 0xFF;
    plaintext[i+5] = (block >> 16) & 0xFF;
    plaintext[i+6] = (block >>  8) & 0xFF;
    plaintext[i+7] =  block         & 0xFF;
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

    if (!gpuIsAvailable()) { fprintf(stderr, "No CUDA devices found.\n"); return 1; }
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

    if (strcmp(argv[1], "-e") == 0) {
        uint64_t prev_cipher = iv;
        size_t total_processed = 0;

        // Encrypt is sequential
        while (total_processed < total_size) {
            size_t to_read    = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(h_in, 1, to_read, input_file);
            if (bytes_read == 0) break;

            size_t process_size = bytes_read;
            bool is_last = (total_processed + bytes_read >= total_size);

            if (is_last && !no_pad) {
                size_t pad_len = 8 - (bytes_read % 8);
                memset(h_in + bytes_read, (uint8_t)pad_len, pad_len);
                process_size = bytes_read + pad_len;
            }

            cudaMemcpyAsync(d_in, h_in, process_size, cudaMemcpyHostToDevice, streams[0]);
            encryptCBCKernel<<<1, 1, 0, streams[0]>>>(d_in, d_out, (int)process_size, d_key, prev_cipher);
            cudaMemcpyAsync(h_out, d_out, process_size, cudaMemcpyDeviceToHost, streams[0]);
            cudaStreamSynchronize(streams[0]);

            prev_cipher = *(uint64_t*)(h_out + process_size - 8);
            fwrite(h_out, 1, process_size, output_file);
            total_processed += bytes_read;
        }

    } else if (strcmp(argv[1], "-d") == 0) {
        uint64_t prev_cipher = iv;
        size_t total_processed = 0;

        // Decrypt is parallel
        while (total_processed < total_size) {
            size_t to_read    = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(h_in, 1, to_read, input_file);
            if (bytes_read == 0) break;

            bool is_last = (total_processed + bytes_read >= total_size);

            int chunk_size  = (int)(bytes_read / NUM_STREAMS) & ~7; // align to 8 bytes
            int num_blocks_per_chunk = chunk_size / 8;
            int threads = 256;
            int blocks  = (num_blocks_per_chunk + threads - 1) / threads;

            for (int s = 0; s < NUM_STREAMS; s++) {
                int offset       = s * chunk_size;
                uint64_t chunk_iv = (s == 0) ? prev_cipher
                                              : *(uint64_t*)(h_in + offset - 8);
                cudaMemcpyAsync(d_in + offset, h_in + offset, chunk_size, cudaMemcpyHostToDevice, streams[s]);
                decryptCBCKernel<<<blocks, threads, 0, streams[s]>>>(d_in + offset, d_out + offset, chunk_size, d_key, chunk_iv);
                cudaMemcpyAsync(h_out + offset, d_out + offset, chunk_size, cudaMemcpyDeviceToHost, streams[s]);
            }
            cudaDeviceSynchronize();

            prev_cipher = *(uint64_t*)(h_in + bytes_read - 8);

            size_t write_size = bytes_read;
            if (is_last && !no_pad) {
                uint8_t pad_len = h_out[bytes_read - 1];
                if (pad_len > 0 && pad_len <= 8)
                    write_size = bytes_read - pad_len;
                else if (pad_len == 0)
                    write_size = bytes_read - 8;
            }

            fwrite(h_out, 1, write_size, output_file);
            total_processed += bytes_read;
        }

    } else {
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
