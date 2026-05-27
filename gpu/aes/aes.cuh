// AES 128. 128-bit key chosen in line with GIFT and PRESENT key sizes
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cuda_runtime.h>

__constant__ uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

__constant__ uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

__constant__ uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

__device__ void print_state(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 3; j >= 0; j--) {
            printf("%02x", state[i][j]);
        }
        printf(" ");
    }
    printf("\n");
}

__device__ static void get_round_keys(const uint64_t *key, uint32_t *round_keys) {
    // use key expansion algo
    static bool initialized = false;
    static uint64_t curr_key[2] = {0, 0};
    static uint32_t curr_round_keys[44] = {0}; // 44 32-bit words for AES-128
    if (initialized && curr_key[0] == key[0] && curr_key[1] == key[1]) {
        memcpy(round_keys, curr_round_keys, sizeof(uint32_t) * 44);
        return;
    }
    uint32_t key_reg0 = (key[0] >> 32) & 0xFFFFFFFF;
    uint32_t key_reg1 = (key[0] >> 0) & 0xFFFFFFFF;
    uint32_t key_reg2 = (key[1] >> 32) & 0xFFFFFFFF;
    uint32_t key_reg3 = (key[1] >> 0) & 0xFFFFFFFF;

    curr_round_keys[0] = key_reg0;
    //printf("Round key 0: %08x\n", curr_round_keys[0]);
    curr_round_keys[1] = key_reg1;
    //printf("Round key 1: %08x\n", curr_round_keys[1]);
    curr_round_keys[2] = key_reg2;
    //printf("Round key 2: %08x\n", curr_round_keys[2]);
    curr_round_keys[3] = key_reg3;
    //printf("Round key 3: %08x\n", curr_round_keys[3]);
    for (int i = 4; i < 44; i++) {
        uint32_t temp = curr_round_keys[i-1];
        if (i%4 == 0) {
            // rotate
            temp = (temp << 8) | (temp >> 24);
            // subbytes
            temp = (sbox[(temp >> 24) & 0xFF] << 24) | (sbox[(temp >> 16) & 0xFF] << 16) | (sbox[(temp >> 8) & 0xFF] << 8) | sbox[temp & 0xFF];
            // rcon
            temp ^= ((uint32_t)rcon[i/4 - 1] << 24);
        }
        curr_round_keys[i] = curr_round_keys[i - 4] ^ temp;
        //printf("Round key %d: %08x\n", i, curr_round_keys[i]);
    }
    memcpy(round_keys, curr_round_keys, sizeof(uint32_t) * 44);
    curr_key[0] = key[0];
    curr_key[1] = key[1];
    initialized = true;
}


__device__ uint8_t xTimes(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0);
}

__device__ uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = xTimes(a);
        b >>= 1;
    }
    return result;
}

__device__void addRoundKey(uint8_t state[4][4], uint32_t roundKey[4], uint8_t newState[4][4]) {
    for (int c = 0; c < 4; c++) {
        //printf("Adding round key %08x for column %d:\n", roundKey[c], c);
        for (int r = 0; r < 4; r++) {
            newState[r][c] = state[r][c] ^ ((roundKey[c] >> (8 * (3-r))) & 0xFF);
            //printf("AddRoundKey: state[%d][%d] = %02x ^ %02x = %02x\n", r, c, state[r][c], (roundKey[c] >> (8 * (3-r))) & 0xFF, newState[r][c]);
        }
    }
}

__device__ void subBytes(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            newState[i][j] = sbox[state[i][j]];
        }
    }
}

__device__ void shiftRows(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            newState[i][j] = state[i][(j + i) % 4];
        }
    }
}

__device__ void mixColumns(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int j = 0; j < 4; j++) {
        newState[0][j] = (uint8_t)(gf_mul(0x02, state[0][j]) ^ gf_mul(0x03, state[1][j]) ^ state[2][j] ^ state[3][j]);
        newState[1][j] = (uint8_t)(state[0][j] ^ gf_mul(0x02, state[1][j]) ^ gf_mul(0x03, state[2][j]) ^ state[3][j]);
        newState[2][j] = (uint8_t)(state[0][j] ^ state[1][j] ^ gf_mul(0x02, state[2][j]) ^ gf_mul(0x03, state[3][j]));
        newState[3][j] = (uint8_t)(gf_mul(0x03, state[0][j]) ^ state[1][j] ^ state[2][j] ^ gf_mul(0x02, state[3][j]));
    }
}

__device__ int aes128_encrypt(const uint64_t *plaintext, const uint64_t *key, uint64_t *ciphertext) {
    
    // state
    uint64_t state1 = plaintext[0];
    uint64_t state2 = plaintext[1];

    uint8_t state[4][4];
    state[0][0] = (state1 >> 56) & 0xFF;
    state[1][0] = (state1 >> 48) & 0xFF;
    state[2][0] = (state1 >> 40) & 0xFF;
    state[3][0] = (state1 >> 32) & 0xFF;
    state[0][1] = (state1 >> 24) & 0xFF;
    state[1][1] = (state1 >> 16) & 0xFF;
    state[2][1] = (state1 >> 8) & 0xFF;
    state[3][1] = (state1 >> 0) & 0xFF;
    state[0][2] = (state2 >> 56) & 0xFF;
    state[1][2] = (state2 >> 48) & 0xFF;
    state[2][2] = (state2 >> 40) & 0xFF;
    state[3][2] = (state2 >> 32) & 0xFF;
    state[0][3] = (state2 >> 24) & 0xFF;
    state[1][3] = (state2 >> 16) & 0xFF;
    state[2][3] = (state2 >> 8) & 0xFF;
    state[3][3] = (state2 >> 0) & 0xFF;
    uint8_t new_state[4][4];

    uint32_t round_keys[44];
    get_round_keys(key, round_keys);

    // state with round key
    uint32_t currRoundKey[4] = {round_keys[0], round_keys[1], round_keys[2], round_keys[3]};
    addRoundKey(state, currRoundKey, new_state);
    std::memcpy(state, new_state, sizeof(state));
    //printf("After initial AddRoundKey:\n");
    //print_state(state);

    // 9 rounds in for loop and 1 round after
    for (int i = 1; i <= 9; i++) {
        // subbytes
        subBytes(state, new_state);
        std::memcpy(state, new_state, sizeof(state));
        //printf("After SubBytes (Round %d):\n", i);
        //print_state(state);

        // shiftrows
        shiftRows(state, new_state);
        std::memcpy(state, new_state, sizeof(state));
        //printf("After ShiftRows (Round %d):\n", i);
        //print_state(state);

        // mixcolumns
        mixColumns(state, new_state);
        std::memcpy(state, new_state, sizeof(state));
        //printf("After MixColumns (Round %d):\n", i);
        //print_state(state);

        // addroundkey
        currRoundKey[0] = round_keys[4*i + 0];
        currRoundKey[1] = round_keys[4*i + 1];
        currRoundKey[2] = round_keys[4*i + 2];
        currRoundKey[3] = round_keys[4*i + 3];
        addRoundKey(state, currRoundKey, new_state);
        std::memcpy(state, new_state, sizeof(state));
        //printf("After AddRoundKey (Round %d):\n", i);
        //print_state(state);
    }
    // subbytes
    subBytes(state, new_state);
    std::memcpy(state, new_state, sizeof(state));
    //printf("After SubBytes (Round 10):\n");
    //print_state(state);

    // shiftrows
    shiftRows(state, new_state);
    std::memcpy(state, new_state, sizeof(state));
    //printf("After ShiftRows (Round 10):\n");
    //print_state(state);

    // addroundkey
    currRoundKey[0] = round_keys[40];
    currRoundKey[1] = round_keys[41];
    currRoundKey[2] = round_keys[42];
    currRoundKey[3] = round_keys[43];
    addRoundKey(state, currRoundKey, new_state);
    std::memcpy(state, new_state, sizeof(state));
    //printf("After AddRoundKey (Round 10):\n");
    //print_state(state);
    state1 = ((uint64_t)state[0][0] << 56) | ((uint64_t)state[1][0] << 48) | ((uint64_t)state[2][0] << 40) | ((uint64_t)state[3][0] << 32) |
             ((uint64_t)state[0][1] << 24) | ((uint64_t)state[1][1] << 16) | ((uint64_t)state[2][1] << 8) | ((uint64_t)state[3][1] << 0);
    state2 = ((uint64_t)state[0][2] << 56) | ((uint64_t)state[1][2] << 48) | ((uint64_t)state[2][2] << 40) | ((uint64_t)state[3][2] << 32) |
             ((uint64_t)state[0][3] << 24) | ((uint64_t)state[1][3] << 16) | ((uint64_t)state[2][3] << 8) | ((uint64_t)state[3][3] << 0);

    ciphertext[0] = state1;
    ciphertext[1] = state2;
    return 0;
}



__device__ void invSubBytes(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            newState[i][j] = inv_sbox[state[i][j]];
        }
    }
}

__device__ void invShiftRows(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            newState[i][(j + i) % 4] = state[i][j];
        }
    }
}

__device__ void invMixColumns(uint8_t state[4][4], uint8_t newState[4][4]) {
    for (int j = 0; j < 4; j++) {
        newState[0][j] = (uint8_t)(gf_mul(0x0e, state[0][j]) ^ gf_mul(0x0b, state[1][j]) ^ gf_mul(0x0d, state[2][j]) ^ gf_mul(0x09, state[3][j]));
        newState[1][j] = (uint8_t)(gf_mul(0x09, state[0][j]) ^ gf_mul(0x0e, state[1][j]) ^ gf_mul(0x0b, state[2][j]) ^ gf_mul(0x0d, state[3][j]));
        newState[2][j] = (uint8_t)(gf_mul(0x0d, state[0][j]) ^ gf_mul(0x09, state[1][j]) ^ gf_mul(0x0e, state[2][j]) ^ gf_mul(0x0b, state[3][j]));
        newState[3][j] = (uint8_t)(gf_mul(0x0b, state[0][j]) ^ gf_mul(0x0d, state[1][j]) ^ gf_mul(0x09, state[2][j]) ^ gf_mul(0x0e, state[3][j]));
    }
}

__device__ int aes128_decrypt(const uint64_t *ciphertext, const uint64_t *key, uint64_t *plaintext) {
    // state
    uint64_t state1 = ciphertext[0];
    uint64_t state2 = ciphertext[1];

    uint8_t state[4][4];
    state[0][0] = (state1 >> 56) & 0xFF;
    state[1][0] = (state1 >> 48) & 0xFF;
    state[2][0] = (state1 >> 40) & 0xFF;
    state[3][0] = (state1 >> 32) & 0xFF;
    state[0][1] = (state1 >> 24) & 0xFF;
    state[1][1] = (state1 >> 16) & 0xFF;
    state[2][1] = (state1 >> 8) & 0xFF;
    state[3][1] = (state1 >> 0) & 0xFF;
    state[0][2] = (state2 >> 56) & 0xFF;
    state[1][2] = (state2 >> 48) & 0xFF;
    state[2][2] = (state2 >> 40) & 0xFF;
    state[3][2] = (state2 >> 32) & 0xFF;
    state[0][3] = (state2 >> 24) & 0xFF;
    state[1][3] = (state2 >> 16) & 0xFF;
    state[2][3] = (state2 >> 8) & 0xFF;
    state[3][3] = (state2 >> 0) & 0xFF;
    uint8_t new_state[4][4];

    uint32_t round_keys[44];
    get_round_keys(key, round_keys);

    // state with round key
    uint32_t currRoundKey[4] = {round_keys[40], round_keys[41], round_keys[42], round_keys[43]};
    addRoundKey(state, currRoundKey, new_state);
    std::memcpy(state, new_state, sizeof(state));

    // 9 rounds in for loop and 1 round after
    for (int i = 9; i >= 1; i--) {
        
        // inverse shiftrows
        invShiftRows(state, new_state);
        std::memcpy(state, new_state, sizeof(state));

        // inverse subbytes
        invSubBytes(state, new_state);
        std::memcpy(state, new_state, sizeof(state));

        // inverse addroundkey
        currRoundKey[0] = round_keys[4*i + 0];
        currRoundKey[1] = round_keys[4*i + 1];
        currRoundKey[2] = round_keys[4*i + 2];
        currRoundKey[3] = round_keys[4*i + 3];
        addRoundKey(state, currRoundKey, new_state);
        std::memcpy(state, new_state, sizeof(state));

        // inverse mixcolumns
        invMixColumns(state, new_state);
        std::memcpy(state, new_state, sizeof(state));
    }
    // inverse shiftrows
    invShiftRows(state, new_state);
    std::memcpy(state, new_state, sizeof(state));

    // inverse subbytes
    invSubBytes(state, new_state);
    std::memcpy(state, new_state, sizeof(state));

    // inverse addroundkey
    currRoundKey[0] = round_keys[0];
    currRoundKey[1] = round_keys[1];
    currRoundKey[2] = round_keys[2];
    currRoundKey[3] = round_keys[3];
    addRoundKey(state, currRoundKey, new_state);
    std::memcpy(state, new_state, sizeof(state));

    state1 = ((uint64_t)state[0][0] << 56) | ((uint64_t)state[1][0] << 48) | ((uint64_t)state[2][0] << 40) | ((uint64_t)state[3][0] << 32) |
             ((uint64_t)state[0][1] << 24) | ((uint64_t)state[1][1] << 16) | ((uint64_t)state[2][1] << 8) | ((uint64_t)state[3][1] << 0);
    state2 = ((uint64_t)state[0][2] << 56) | ((uint64_t)state[1][2] << 48) | ((uint64_t)state[2][2] << 40) | ((uint64_t)state[3][2] << 32) |
             ((uint64_t)state[0][3] << 24) | ((uint64_t)state[1][3] << 16) | ((uint64_t)state[2][3] << 8) | ((uint64_t)state[3][3] << 0);

    plaintext[0] = state1;
    plaintext[1] = state2;
    return 0;
}