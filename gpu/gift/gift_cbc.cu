#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../utils/gpu_info.cuh"
#include "../utils/timer.hpp"
#include "gift.cuh"
#include "gift128_t_tables.cuh"

#define BUFFER_SIZE (8 * 1024 * 1024)
#define GIFT128_BLOCK_BYTES 16
#define USE_GIFT_CBC_TTABLE 0

__constant__ Gift128Block d_gift128_RK[GIFT128_ROUNDS];

static void host_xor_bit(Gift128Block* x, int pos, uint32_t bit) {
    if (!bit) return;

    if (pos < 64)
        x->lo ^= (1ull << pos);
    else
        x->hi ^= (1ull << (pos - 64));
}

static void init_gift128_round_masks(const uint16_t key[8]) {
    Gift128Block h_RK[GIFT128_ROUNDS];

    uint16_t k[8];
    for (int i = 0; i < 8; i++)
        k[i] = key[i];

    uint8_t c = 0;

    for (int r = 0; r < GIFT128_ROUNDS; r++) {
        h_RK[r].lo = 0;
        h_RK[r].hi = 0;

        int c5 = (c >> 5) & 1;
        int c4 = (c >> 4) & 1;
        c = (uint8_t)(((c << 1) & 0x3e) | (c5 ^ c4 ^ 1));

        uint32_t U = ((uint32_t)k[5] << 16) | k[4];
        uint32_t V = ((uint32_t)k[1] << 16) | k[0];

        for (int i = 0; i < 32; i++) {
            host_xor_bit(&h_RK[r], 4*i + 2, (U >> i) & 1u);
            host_xor_bit(&h_RK[r], 4*i + 1, (V >> i) & 1u);
        }

        host_xor_bit(&h_RK[r], 127, 1);
        host_xor_bit(&h_RK[r], 23, (c >> 5) & 1u);
        host_xor_bit(&h_RK[r], 19, (c >> 4) & 1u);
        host_xor_bit(&h_RK[r], 15, (c >> 3) & 1u);
        host_xor_bit(&h_RK[r], 11, (c >> 2) & 1u);
        host_xor_bit(&h_RK[r], 7,  (c >> 1) & 1u);
        host_xor_bit(&h_RK[r], 3,  (c >> 0) & 1u);

        uint16_t k0 = k[0];
        uint16_t k1 = k[1];
        uint16_t k2 = k[2];
        uint16_t k3 = k[3];
        uint16_t k4_ = k[4];
        uint16_t k5_ = k[5];
        uint16_t k6 = k[6];
        uint16_t k7 = k[7];

        k[7] = rotr16(k1, 2);
        k[6] = rotr16(k0, 12);
        k[5] = k7;
        k[4] = k6;
        k[3] = k5_;
        k[2] = k4_;
        k[1] = k3;
        k[0] = k2;
    }
    cudaMemcpyToSymbol(d_gift128_RK, h_RK, sizeof(h_RK));
}

__device__ __forceinline__ uint8_t get_nibble(Gift128Block x, int n) {
    if (n < 16)
        return (uint8_t)((x.lo >> (4 * n)) & 0xf);
    else
        return (uint8_t)((x.hi >> (4 * (n - 16))) & 0xf);
}

__device__ __forceinline__ Gift128Block gift128_round_ttable(Gift128Block state) {
    Gift128Block out;
    out.lo = 0;
    out.hi = 0;

    #pragma unroll
    for (int n = 0; n < 32; n++) {
        uint8_t nib = get_nibble(state, n);
        Gift128Block t = d_gift128_T[n][nib];

        out.lo ^= t.lo;
        out.hi ^= t.hi;
    }

    return out;
}

__device__ __forceinline__ Gift128Block gift128_encrypt(Gift128Block state) {
    #pragma unroll
    for (int r = 0; r < GIFT128_ROUNDS; r++) {
        state = gift128_round_ttable(state);

        state.lo ^= d_gift128_RK[r].lo;
        state.hi ^= d_gift128_RK[r].hi;
    }

    return state;
}

__global__ void encryptCBCKernel_ttable(const uint8_t* plaintext, uint8_t* ciphertext, size_t length, Gift128Block iv) {
    Gift128Block prev = iv;
    size_t nblocks = length / GIFT128_BLOCK_BYTES;

    for (size_t b = 0; b < nblocks; b++) {
        Gift128Block x = gift_load_block(plaintext + b * GIFT128_BLOCK_BYTES);

        x.lo ^= prev.lo;
        x.hi ^= prev.hi;

        Gift128Block c = gift128_encrypt(x);

        gift_store_block(ciphertext + b * GIFT128_BLOCK_BYTES, c);

        prev = c;
    }
}

__global__ void encryptCBCKernel_bitslice(
    const uint8_t* plaintext,
    uint8_t* ciphertext,
    size_t length,
    const uint16_t* key,
    Gift128Block iv
) {
    int lane = threadIdx.x & 31;

    uint16_t local_key[8];
    #pragma unroll
    for (int i = 0; i < 8; i++)
        local_key[i] = key[i];

    Gift128Block prev = iv;
    size_t nblocks = length / GIFT128_BLOCK_BYTES;

    for (size_t b = 0; b < nblocks; b++) {
        Gift128Block x;
        x.lo = 0;
        x.hi = 0;

        if (lane == 0) {
            x = gift_load_block(plaintext + b * GIFT128_BLOCK_BYTES);
            x.lo ^= prev.lo;
            x.hi ^= prev.hi;
        }

        Gift128Block c = gift128_encrypt_bl(x, local_key, FULL_MASK);

        c.lo = __shfl_sync(FULL_MASK, c.lo, 0);
        c.hi = __shfl_sync(FULL_MASK, c.hi, 0);

        if (lane == 0)
            gift_store_block(ciphertext + b * GIFT128_BLOCK_BYTES, c);

        prev = c;
    }
}

__global__ void decryptCBCKernel(const uint8_t* ciphertext, uint8_t* plaintext, size_t length, const uint16_t* key, Gift128Block iv) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    int lane = threadIdx.x & 31;
    int warp_global = tid >> 5;

    size_t block_idx = (size_t)warp_global * 32 + lane;
    size_t byte_idx = block_idx * GIFT128_BLOCK_BYTES;

    bool active = byte_idx < length;
    unsigned mask = __ballot_sync(FULL_MASK, active);
    if (mask == 0) return;

    uint16_t local_key[8];
    #pragma unroll
    for (int i = 0; i < 8; i++)
        local_key[i] = key[i];

    Gift128Block c;
    c.lo = 0;
    c.hi = 0;

    if (active)
        c = gift_load_block(ciphertext + byte_idx);

    Gift128Block dec = gift128_decrypt_warp_bitslice(c, local_key, mask);

    if (active) {
        Gift128Block prev;

        if (block_idx == 0) {
            prev = iv;
        } else {
            prev = gift_load_block(ciphertext + byte_idx - GIFT128_BLOCK_BYTES);
        }

        Gift128Block p;
        p.lo = dec.lo ^ prev.lo;
        p.hi = dec.hi ^ prev.hi;

        gift_store_block(plaintext + byte_idx, p);
    }
}

static uint64_t load_be64_host(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |
           ((uint64_t)p[7] <<  0);
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

    iv->hi = load_be64_host(iv_bytes);
    iv->lo = load_be64_host(iv_bytes + 8);
}

static Gift128Block host_load_block(const uint8_t* p) {
    Gift128Block x;
    x.hi = load_be64_host(p);
    x.lo = load_be64_host(p + 8);
    return x;
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
    fseek(input_file, 0, SEEK_END);
    size_t total_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    uint16_t key[8];
    hex_to_key(argv[3], key);

    init_gift128_round_masks(key);

    Gift128Block iv;
    hex_to_iv(argv[4], &iv);

    FILE* output_file = fopen(argv[5], "wb");

    // Pinned host buffers
    uint8_t* h_in;
    uint8_t* h_out;
    cudaMallocHost(&h_in,  BUFFER_SIZE + GIFT128_BLOCK_BYTES);
    cudaMallocHost(&h_out, BUFFER_SIZE + GIFT128_BLOCK_BYTES);

    // Device buffers and key
    uint8_t* d_in;
    uint8_t* d_out;
    uint16_t* d_key;

    cudaMalloc(&d_in,  BUFFER_SIZE + GIFT128_BLOCK_BYTES);
    cudaMalloc(&d_out, BUFFER_SIZE + GIFT128_BLOCK_BYTES);
    cudaMalloc(&d_key, 8 * sizeof(uint16_t));
    cudaMemcpy(d_key, key, 8 * sizeof(uint16_t), cudaMemcpyHostToDevice);

    Timer t;
    t.start();

    size_t total_processed = 0;

    while (total_processed < total_size) {
        size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);

        size_t bytes_read = fread(h_in, 1, to_read, input_file);
        if (bytes_read == 0) break;

        size_t process_size = bytes_read;
        bool is_last = (total_processed + bytes_read >= total_size);

        if (strcmp(argv[1], "-e") == 0 && is_last && !no_pad) {
            size_t pad_len = GIFT128_BLOCK_BYTES - (bytes_read % GIFT128_BLOCK_BYTES);
            if (pad_len == 0) pad_len = GIFT128_BLOCK_BYTES;
            memset(h_in + bytes_read, (uint8_t)pad_len, pad_len);
            process_size = bytes_read + pad_len;
        }

        cudaMemcpy(d_in, h_in, process_size, cudaMemcpyHostToDevice);
        
        if (strcmp(argv[1], "-e") == 0) {
            #if USE_GIFT_CBC_TTABLE
            encryptCBCKernel_ttable<<<1, 1>>>(d_in, d_out, process_size, iv);
            #else
            encryptCBCKernel_bitslice<<<1, 32>>>(d_in, d_out, process_size, d_key, iv);
            #endif
        } else {
            int num_blocks = process_size / GIFT128_BLOCK_BYTES;
            int threads = 256;
            int warps = (num_blocks + 31) / 32;
            int blocks = (warps * 32 + threads - 1) / threads;
            if (blocks == 0) blocks = 1;
        
            decryptCBCKernel<<<blocks, threads>>>(d_in, d_out, process_size, d_key, iv);
        }
        
        cudaDeviceSynchronize();
        cudaMemcpy(h_out, d_out, process_size, cudaMemcpyDeviceToHost);

        size_t write_size = process_size;

        if (strcmp(argv[1], "-d") == 0 && is_last && !no_pad) {
            uint8_t pad_len = h_out[process_size - 1];
            write_size = process_size - pad_len;
        }

        fwrite(h_out, 1, write_size, output_file);

        if (strcmp(argv[1], "-e") == 0) {
            iv = host_load_block(h_out + process_size - GIFT128_BLOCK_BYTES);
        } else {
            iv = host_load_block(h_in + process_size - GIFT128_BLOCK_BYTES);
        }
        total_processed += bytes_read;
    }

    fprintf(stdout, "[timer] total: %ld ms\n", t.stopMs());

    cudaFree(d_in);
    cudaFree(d_out);
    cudaFree(d_key);

    cudaFreeHost(h_in);
    cudaFreeHost(h_out);

    fclose(input_file);
    fclose(output_file);

    return 0;
}