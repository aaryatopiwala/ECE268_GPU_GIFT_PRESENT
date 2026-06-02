#pragma once

#include <stdint.h>
#include <cuda_runtime.h>

#define GIFT128_ROUNDS 40
#define FULL_MASK 0xffffffffu
__constant__ uint32_t d_gift128_U[GIFT128_ROUNDS];
__constant__ uint32_t d_gift128_V[GIFT128_ROUNDS];
__constant__ uint8_t  d_gift128_RC[GIFT128_ROUNDS];

struct Gift128Block {
    uint64_t lo;
    uint64_t hi;
};

#include "gift128_t_tables.cuh"

__host__ __device__ __forceinline__ uint16_t rotr16(uint16_t x, int r) {
    return (uint16_t)((x >> r) | (x << (16 - r)));
}

__device__ __forceinline__ uint64_t gift_load_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |
           ((uint64_t)p[7] <<  0);
}

__device__ __forceinline__ void gift_store_be64(uint8_t* p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >>  8);
    p[7] = (uint8_t)(x >>  0);
}

__device__ __forceinline__ Gift128Block gift_load_block(const uint8_t* p) {
    Gift128Block x;
    x.hi = gift_load_be64(p);
    x.lo = gift_load_be64(p + 8);
    return x;
}

__device__ __forceinline__ void gift_store_block(uint8_t* p, Gift128Block x) {
    gift_store_be64(p, x.hi);
    gift_store_be64(p + 8, x.lo);
}

__device__ __forceinline__ int gift128_perm_index(int i) {
    int imod16 = i & 15;
    int imod4  = i & 3;

    return 4 * (i >> 4) + 32 * ((3 * (imod16 >> 2) + imod4) & 3) + imod4;
}

__host__ __device__ __forceinline__ uint8_t gift_sbox(uint8_t x) {
    const uint8_t s[16] = {
        0x1, 0xa, 0x4, 0xc,
        0x6, 0xf, 0x3, 0x9,
        0x2, 0xd, 0xb, 0x7,
        0x5, 0x0, 0x8, 0xe
    };

    return s[x & 0xf];
}

__device__ __forceinline__ uint8_t gift_inv_sbox(uint8_t x) {
    const uint8_t inv[16] = {
        0xd, 0x0, 0x8, 0x6,
        0x2, 0xc, 0x4, 0xb,
        0xe, 0x7, 0x1, 0xa,
        0x3, 0x9, 0xf, 0x5
    };

    return inv[x & 0xf];
}

__device__ __forceinline__ void gift128_round_keys(const uint16_t key[8], uint32_t U[GIFT128_ROUNDS], uint32_t V[GIFT128_ROUNDS], uint8_t RC[GIFT128_ROUNDS]) {
    uint16_t k[8];

    #pragma unroll
    for (int i = 0; i < 8; i++)
        k[i] = key[i];
    uint8_t c = 0;

    #pragma unroll
    for (int r = 0; r < GIFT128_ROUNDS; r++) {
        int c5 = (c >> 5) & 1;
        int c4 = (c >> 4) & 1;
        c = (uint8_t)(((c << 1) & 0x3e) | (c5 ^ c4 ^ 1));

        RC[r] = c;
        U[r] = ((uint32_t)k[5] << 16) | k[4];
        V[r] = ((uint32_t)k[1] << 16) | k[0];

        uint16_t k0 = k[0];
        uint16_t k1 = k[1];
        uint16_t k2 = k[2];
        uint16_t k3 = k[3];
        uint16_t k4 = k[4];
        uint16_t k5 = k[5];
        uint16_t k6 = k[6];
        uint16_t k7 = k[7];

        k[7] = rotr16(k1, 2);
        k[6] = rotr16(k0, 12);
        k[5] = k7;
        k[4] = k6;
        k[3] = k5;
        k[2] = k4;
        k[1] = k3;
        k[0] = k2;
    }
}

static void init_gift128_round_keys_device(const uint16_t key[8]) {
    uint32_t h_U[GIFT128_ROUNDS];
    uint32_t h_V[GIFT128_ROUNDS];
    uint8_t  h_RC[GIFT128_ROUNDS];

    uint16_t k[8];
    for (int i = 0; i < 8; i++)
        k[i] = key[i];

    uint8_t c = 0;

    for (int r = 0; r < GIFT128_ROUNDS; r++) {
        int c5 = (c >> 5) & 1;
        int c4 = (c >> 4) & 1;
        c = (uint8_t)(((c << 1) & 0x3e) | (c5 ^ c4 ^ 1));

        h_RC[r] = c;
        h_U[r] = ((uint32_t)k[5] << 16) | k[4];
        h_V[r] = ((uint32_t)k[1] << 16) | k[0];

        uint16_t k0 = k[0];
        uint16_t k1 = k[1];
        uint16_t k2 = k[2];
        uint16_t k3 = k[3];
        uint16_t k4 = k[4];
        uint16_t k5 = k[5];
        uint16_t k6 = k[6];
        uint16_t k7 = k[7];

        k[7] = rotr16(k1, 2);
        k[6] = rotr16(k0, 12);
        k[5] = k7;
        k[4] = k6;
        k[3] = k5;
        k[2] = k4;
        k[1] = k3;
        k[0] = k2;
    }

    cudaMemcpyToSymbol(d_gift128_U,  h_U,  sizeof(h_U));
    cudaMemcpyToSymbol(d_gift128_V,  h_V,  sizeof(h_V));
    cudaMemcpyToSymbol(d_gift128_RC, h_RC, sizeof(h_RC));
}

__device__ __forceinline__ void gift128_pack(uint32_t p[128], Gift128Block x, unsigned mask) {
    #pragma unroll
    for (int i = 0; i < 64; i++)
        p[i] = __ballot_sync(mask, (x.lo >> i) & 1ull);

    #pragma unroll
    for (int i = 0; i < 64; i++)
        p[64 + i] = __ballot_sync(mask, (x.hi >> i) & 1ull);
}

__device__ __forceinline__ Gift128Block gift128_unpack(const uint32_t p[128], int lane) {
    Gift128Block x;
    x.lo = 0;
    x.hi = 0;

    #pragma unroll
    for (int i = 0; i < 64; i++)
        x.lo |= ((uint64_t)((p[i] >> lane) & 1u)) << i;

    #pragma unroll
    for (int i = 0; i < 64; i++)
        x.hi |= ((uint64_t)((p[64 + i] >> lane) & 1u)) << i;

    return x;
}

__device__ __forceinline__ void gift128_subcells(uint32_t p[128], bool inverse) {
    #pragma unroll
    for (int n = 0; n < 32; n++) {
        uint32_t x0 = p[4*n + 0];
        uint32_t x1 = p[4*n + 1];
        uint32_t x2 = p[4*n + 2];
        uint32_t x3 = p[4*n + 3];

        uint32_t y0 = 0;
        uint32_t y1 = 0;
        uint32_t y2 = 0;
        uint32_t y3 = 0;

        #pragma unroll
        for (int v = 0; v < 16; v++) {
            uint32_t term = 0xffffffffu;

            term &= (v & 1) ? x0 : ~x0;
            term &= (v & 2) ? x1 : ~x1;
            term &= (v & 4) ? x2 : ~x2;
            term &= (v & 8) ? x3 : ~x3;

            uint8_t y = inverse ? gift_inv_sbox((uint8_t)v) : gift_sbox((uint8_t)v);

            if (y & 1) y0 |= term;
            if (y & 2) y1 |= term;
            if (y & 4) y2 |= term;
            if (y & 8) y3 |= term;
        }

        p[4*n + 0] = y0;
        p[4*n + 1] = y1;
        p[4*n + 2] = y2;
        p[4*n + 3] = y3;
    }
}

__device__ __forceinline__ void gift128_permute(uint32_t p[128]) {
    uint32_t t[128];

    #pragma unroll
    for (int i = 0; i < 128; i++)
        t[gift128_perm_index(i)] = p[i];

    #pragma unroll
    for (int i = 0; i < 128; i++)
        p[i] = t[i];
}

__device__ __forceinline__ void gift128_inv_permute(uint32_t p[128]) {
    uint32_t t[128];

    #pragma unroll
    for (int i = 0; i < 128; i++)
        t[i] = p[gift128_perm_index(i)];

    #pragma unroll
    for (int i = 0; i < 128; i++)
        p[i] = t[i];
}

__device__ __forceinline__ void gift128_add_key(uint32_t p[128], uint32_t U, uint32_t V,uint8_t rc) {
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if ((U >> i) & 1u) p[4*i + 2] ^= 0xffffffffu;
        if ((V >> i) & 1u) p[4*i + 1] ^= 0xffffffffu;
    }

    p[127] ^= 0xffffffffu;

    if ((rc >> 5) & 1u) p[23] ^= 0xffffffffu;
    if ((rc >> 4) & 1u) p[19] ^= 0xffffffffu;
    if ((rc >> 3) & 1u) p[15] ^= 0xffffffffu;
    if ((rc >> 2) & 1u) p[11] ^= 0xffffffffu;
    if ((rc >> 1) & 1u) p[7]  ^= 0xffffffffu;
    if ((rc >> 0) & 1u) p[3]  ^= 0xffffffffu;
}

__device__ __forceinline__ Gift128Block gift128_encrypt_bl(Gift128Block in, unsigned mask) {
    uint32_t p[128];

    gift128_pack(p, in, mask);

    #pragma unroll
    for (int r = 0; r < GIFT128_ROUNDS; r++) {
        gift128_subcells(p, false);
        gift128_permute(p);
        gift128_add_key(p, d_gift128_U[r], d_gift128_V[r], d_gift128_RC[r]);
    }

    return gift128_unpack(p, threadIdx.x & 31);
}

__device__ __forceinline__ Gift128Block gift128_decrypt_warp_bitslice(Gift128Block in, unsigned mask) {
    uint32_t p[128];

    gift128_pack(p, in, mask);

    for (int r = GIFT128_ROUNDS - 1; r >= 0; r--) {
        gift128_add_key(p, d_gift128_U[r], d_gift128_V[r], d_gift128_RC[r]);
        gift128_inv_permute(p);
        gift128_subcells(p, true);
    }

    return gift128_unpack(p, threadIdx.x & 31);
}

