#include <cstdint>
#include <cstring>
#include <cstdio>

#define USE_CPU_GIFT_TTABLE 1

const uint8_t sbox[16] = {
    0x1, 0xA, 0x4, 0xC, 0x6, 0xF, 0x3, 0x9,
    0x2, 0xD, 0xB, 0x7, 0x5, 0x0, 0x8, 0xE
};

const uint8_t p_layer[128] = {
    0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
    4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
    8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
};

const uint8_t round_constants[48] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24
};


static void get_round_keys(const uint64_t *key, uint64_t *round_keys) {
    static uint64_t curr_key[2] = {0, 0};
    static uint64_t curr_round_keys[80] = {0};
    static bool valid = false;

    uint64_t key_reg1 = key[0];
    uint64_t key_reg2 = key[1];
    if (!valid || curr_key[0] != key[0] || curr_key[1] != key[1]) {
        
        for (int i = 0; i < 40; i++){
            // 16-bit 5 and 16-bit 4 concat
            uint64_t u = (((key_reg2 >> 16) & 0xFFFF) << 16) | (((key_reg2 >> 0) & 0xFFFF) << 0);
            // 16-bit 1 and 16-bit 0 concat
            uint64_t v = (((key_reg1 >> 16) & 0xFFFF) << 16) | (((key_reg1 >> 0) & 0xFFFF) << 0);
            curr_round_keys[2*i] = u;
            curr_round_keys[2*i + 1] = v;

            // update key state reg
            // extract 8 16-bit groups
            uint16_t key_groups[8];
            key_groups[0] = (key_reg1 >> 0) & 0xFFFF;
            key_groups[1] = (key_reg1 >> 16) & 0xFFFF;
            key_groups[2] = (key_reg1 >> 32) & 0xFFFF;
            key_groups[3] = (key_reg1 >> 48) & 0xFFFF;
            key_groups[4] = (key_reg2 >> 0) & 0xFFFF;
            key_groups[5] = (key_reg2 >> 16) & 0xFFFF;
            key_groups[6] = (key_reg2 >> 32) & 0xFFFF;
            key_groups[7] = (key_reg2 >> 48) & 0xFFFF;

            // rotate right group 1 by 2 bits
            key_groups[1] = (key_groups[1] >> 2) | (key_groups[1] << (16 - 2));
            // rotate right group 0 by 12 bits
            key_groups[0] = (key_groups[0] >> 12) | (key_groups[0] << (16 - 12));

            // concat in order of 1, 0, 7, 6, 5, 4, 3, 2
            key_reg1 = ((uint64_t)key_groups[2] << 0) | ((uint64_t)key_groups[3] << 16) | ((uint64_t)key_groups[4] << 32) | ((uint64_t)key_groups[5] << 48);
            key_reg2 = ((uint64_t)key_groups[6] << 0) | ((uint64_t)key_groups[7] << 16) | ((uint64_t)key_groups[0] << 32) | ((uint64_t)key_groups[1] << 48);
        }
        valid = true;
        curr_key[0] = key[0];
        curr_key[1] = key[1];
    }

    memcpy(round_keys, curr_round_keys, sizeof(uint64_t) * 80);
}

static uint64_t gift128_T[32][16][2];
static bool gift128_T_valid = false;

static void init_gift128_ttable_cpu() {
    if (gift128_T_valid) return;

    memset(gift128_T, 0, sizeof(gift128_T));

    for (int n = 0; n < 32; n++) {
        for (int v = 0; v < 16; v++) {
            uint8_t y = sbox[v];

            uint64_t out1 = 0;
            uint64_t out2 = 0;

            for (int b = 0; b < 4; b++) {
                if ((y >> b) & 1) {
                    int src_pos = 4 * n + b;
                    int dst_pos = p_layer[src_pos];

                    if (dst_pos < 64)
                        out1 |= (1ULL << dst_pos);
                    else
                        out2 |= (1ULL << (dst_pos - 64));
                }
            }

            gift128_T[n][v][0] = out1;
            gift128_T[n][v][1] = out2;
        }
    }

    gift128_T_valid = true;
}

static void get_round_masks_cpu(const uint64_t *key, uint64_t *round_masks) {
    static uint64_t curr_key[2] = {0, 0};
    static uint64_t curr_masks[80] = {0};
    static bool valid = false;

    if (!valid || curr_key[0] != key[0] || curr_key[1] != key[1]) {
        uint64_t round_keys[80];
        get_round_keys(key, round_keys);

        for (int i = 0; i < 40; i++) {
            uint64_t mask1 = 0;
            uint64_t mask2 = 0;

            uint64_t u = round_keys[2*i];
            uint64_t v = round_keys[2*i + 1];

            for (int j = 0; j < 32; j++) {
                uint64_t u_bit = (u >> j) & 1ULL;
                uint64_t v_bit = (v >> j) & 1ULL;

                int u_index = 4*j + 2;
                int v_index = 4*j + 1;

                if (u_bit) {
                    if (u_index < 64)
                        mask1 ^= (1ULL << u_index);
                    else
                        mask2 ^= (1ULL << (u_index - 64));
                }

                if (v_bit) {
                    if (v_index < 64)
                        mask1 ^= (1ULL << v_index);
                    else
                        mask2 ^= (1ULL << (v_index - 64));
                }
            }

            mask2 ^= (1ULL << 63);

            mask1 ^= (uint64_t)((round_constants[i] >> 5) & 1) << 23;
            mask1 ^= (uint64_t)((round_constants[i] >> 4) & 1) << 19;
            mask1 ^= (uint64_t)((round_constants[i] >> 3) & 1) << 15;
            mask1 ^= (uint64_t)((round_constants[i] >> 2) & 1) << 11;
            mask1 ^= (uint64_t)((round_constants[i] >> 1) & 1) << 7;
            mask1 ^= (uint64_t)((round_constants[i] >> 0) & 1) << 3;

            curr_masks[2*i] = mask1;
            curr_masks[2*i + 1] = mask2;
        }

        curr_key[0] = key[0];
        curr_key[1] = key[1];
        valid = true;
    }

    memcpy(round_masks, curr_masks, sizeof(uint64_t) * 80);
}

static int gift128_encrypt_ttable_cpu(const uint64_t *plaintext, const uint64_t *key, uint64_t *ciphertext) {
    init_gift128_ttable_cpu();

    uint64_t round_masks[80];
    get_round_masks_cpu(key, round_masks);

    uint64_t state1 = plaintext[0];
    uint64_t state2 = plaintext[1];

    for (int r = 0; r < 40; r++) {
        uint64_t new_state1 = 0;
        uint64_t new_state2 = 0;

        for (int n = 0; n < 16; n++) {
            uint8_t nib = (state1 >> (4*n)) & 0xF;
            new_state1 ^= gift128_T[n][nib][0];
            new_state2 ^= gift128_T[n][nib][1];
        }

        for (int n = 0; n < 16; n++) {
            uint8_t nib = (state2 >> (4*n)) & 0xF;
            int idx = n + 16;
            new_state1 ^= gift128_T[idx][nib][0];
            new_state2 ^= gift128_T[idx][nib][1];
        }

        state1 = new_state1 ^ round_masks[2*r];
        state2 = new_state2 ^ round_masks[2*r + 1];
    }

    ciphertext[0] = state1;
    ciphertext[1] = state2;

    return 0;
}


int gift128_encrypt_reference(const uint64_t *plaintext, const uint64_t *key, uint64_t *ciphertext) {
    uint64_t state1 = plaintext[0];
    uint64_t state2 = plaintext[1];

    // make/get round keys
    uint64_t round_keys[80]; // 40 rounds for GIFT-128, 2 64-bit words per round
    get_round_keys(key, round_keys);

    // 40 rounds for GIFT-128
    for (int i = 0; i < 40; i++) {
        //printf("Round %d: state1 = %016lx, state2 = %016lx\n", i, state1, state2);
        // sbox
        for (int j = 0; j < 16; j++) {
            uint8_t fourbits = (state1 >> (4 * j)) & 0xF;
            fourbits = sbox[fourbits];
            state1 = (state1 & ~((uint64_t)0xF << (4 * j))) | ((uint64_t)fourbits << (4 * j));
        }
        for (int j = 0; j < 16; j++) {
            uint8_t fourbits = (state2 >> (4 * j)) & 0xF;
            fourbits = sbox[fourbits];
            state2 = (state2 & ~((uint64_t)0xF << (4 * j))) | ((uint64_t)fourbits << (4 * j));
        }
        //printf("After sbox: state1 = %016lx, state2 = %016lx\n", state1, state2);

        // p-layer
        uint64_t new_state1 = 0;
        uint64_t new_state2 = 0;
        for (int j = 0; j < 64; j++) {
            uint64_t bit1 = (state1 >> j) & 1;
            uint64_t bit2 = (state2 >> j) & 1;
            uint64_t p_index1 = p_layer[j];
            uint64_t p_index2 = p_layer[j + 64];
            if (p_index1 < 64) {
                new_state1 |= ((uint64_t)bit1 << p_index1);
            } else {
                new_state2 |= ((uint64_t)bit1 << (p_index1 - 64));
            }
            if (p_index2 < 64) {
                new_state1 |= ((uint64_t)bit2 << p_index2);
            } else {
                new_state2 |= ((uint64_t)bit2 << (p_index2 - 64));
            }
        }
        state1 = new_state1;
        state2 = new_state2;
        //printf("After p-layer: state1 = %016lx, state2 = %016lx\n", state1, state2);
        // round key addition
        uint64_t u = round_keys[2*i];
        uint64_t v = round_keys[2*i + 1];
        for (int j = 0; j < 32; j++){
            uint8_t bit1 = (u >> j) & 1;
            uint8_t bit2 = (v >> j) & 1;
            uint64_t u_index = 4*j+2;
            uint64_t v_index = 4*j+1;
            if (u_index < 64) {
                state1 ^= ((uint64_t)bit1 << u_index);
            } else {
                state2 ^= ((uint64_t)bit1 << (u_index - 64));
            }
            if (v_index < 64) {
                state1 ^= ((uint64_t)bit2 << v_index);
            } else {
                state2 ^= ((uint64_t)bit2 << (v_index - 64));
            }
        }

        // 6 bit round constant addition
        // bit n-1
        state2 ^= ((uint64_t)1 << 63);
        // bit 23
        state1 ^= (uint64_t)((round_constants[i] >> 5) & 1) << 23;
        // bit 19
        state1 ^= (uint64_t)((round_constants[i] >> 4) & 1) << 19;
        // bit 15
        state1 ^= (uint64_t)((round_constants[i] >> 3) & 1) << 15;
        // bit 11
        state1 ^= (uint64_t)((round_constants[i] >> 2) & 1) << 11;
        // bit 7
        state1 ^= (uint64_t)((round_constants[i] >> 1) & 1) << 7;
        // bit 3
        state1 ^= (uint64_t)((round_constants[i] >> 0) & 1) << 3;
        //printf("After round key and constant addition: state1 = %016lx, state2 = %016lx\n", state1, state2);
    }

    uint64_t final_state[2] = {state1, state2};
    memcpy(ciphertext, &final_state, 16); // Copy the final state to ciphertext
    return 0; // Return 0 on success
}

int gift128_encrypt(const uint64_t *plaintext, const uint64_t *key, uint64_t *ciphertext) {
#if USE_CPU_GIFT_TTABLE
    return gift128_encrypt_ttable_cpu(plaintext, key, ciphertext);
#else
    return gift128_encrypt_reference(plaintext, key, ciphertext);
#endif
}

const uint8_t inv_sbox[16] = {
    0xD, 0x0, 0x8, 0x6, 0x2, 0xC, 0x4, 0xB,
    0xE, 0x7, 0x1, 0xA, 0x3, 0x9, 0xF, 0x5
};

const uint8_t inv_p_layer[128] = {
    0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
    64, 69, 74, 79, 80, 85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127,
    12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
    76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107, 124, 113, 118, 123,
    8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
    72, 77, 66, 71, 88, 93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119,
    4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51,
    68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115
};

int gift128_decrypt(const uint64_t *ciphertext, const uint64_t *key, uint64_t *plaintext) {
    uint64_t state1 = ciphertext[0];
    uint64_t state2 = ciphertext[1];

    // make/get round keys
    uint64_t round_keys[80]; // 40 rounds for GIFT-128, 2 64-bit words per round
    get_round_keys(key, round_keys);

    // 40 rounds for GIFT-128
    for (int i = 39; i >= 0; i--) {
        //printf("Round %d: state1 = %016lx, state2 = %016lx\n", i, state1, state2);
        // inverse round key addition
        uint64_t u = round_keys[2*i];
        uint64_t v = round_keys[2*i + 1];

        for (int j = 0; j < 32; j++){
            uint8_t bit1 = (u >> j) & 1;
            uint8_t bit2 = (v >> j) & 1;
            uint64_t u_index = 4*j+2;
            uint64_t v_index = 4*j+1;
            if (u_index < 64) {
                state1 ^= ((uint64_t)bit1 << u_index);
            } else {
                state2 ^= ((uint64_t)bit1 << (u_index - 64));
            }
            if (v_index < 64) {
                state1 ^= ((uint64_t)bit2 << v_index);
            } else {
                state2 ^= ((uint64_t)bit2 << (v_index - 64));
            }
        }

        // 6 bit round constant addition
        // bit n-1
        state2 ^= ((uint64_t)1 << 63);
        // bit 23
        state1 ^= (uint64_t)((round_constants[i] >> 5) & 1) << 23;
        // bit 19
        state1 ^= (uint64_t)((round_constants[i] >> 4) & 1) << 19;
        // bit 15
        state1 ^= (uint64_t)((round_constants[i] >> 3) & 1) << 15;
        // bit 11
        state1 ^= (uint64_t)((round_constants[i] >> 2) & 1) << 11;
        // bit 7
        state1 ^= (uint64_t)((round_constants[i] >> 1) & 1) << 7;
        // bit 3
        state1 ^= (uint64_t)((round_constants[i] >> 0) & 1) << 3;

        //printf("After round key addition and constant addition: state1 = %016lx, state2 = %016lx\n", state1, state2);


        // inverse p-layer
        uint64_t new_state1 = 0;
        uint64_t new_state2 = 0;
        for (int j = 0; j < 64; j++) {
            uint64_t bit1 = (state1 >> j) & 1;
            uint64_t bit2 = (state2 >> j) & 1;
            uint64_t p_index1 = inv_p_layer[j];
            uint64_t p_index2 = inv_p_layer[j + 64];
            if (p_index1 < 64) {
                new_state1 |= ((uint64_t)bit1 << p_index1);
            } else {
                new_state2 |= ((uint64_t)bit1 << (p_index1 - 64));
            }
            if (p_index2 < 64) {
                new_state1 |= ((uint64_t)bit2 << p_index2);
            } else {
                new_state2 |= ((uint64_t)bit2 << (p_index2 - 64));
            }
        }
        state1 = new_state1;
        state2 = new_state2;
        //printf("After inverse p-layer: state1 = %016lx, state2 = %016lx\n", state1, state2);

        // inverse sbox
        for (int j = 0; j < 16; j++) {
            uint8_t fourbits = (state1 >> (4 * j)) & 0xF;
            fourbits = inv_sbox[fourbits];
            state1 = (state1 & ~((uint64_t)0xF << (4 * j))) | ((uint64_t)fourbits << (4 * j));
        }
        for (int j = 0; j < 16; j++) {
            uint8_t fourbits = (state2 >> (4 * j)) & 0xF;
            fourbits = inv_sbox[fourbits];
            state2 = (state2 & ~((uint64_t)0xF << (4 * j))) | ((uint64_t)fourbits << (4 * j));
        }

        //printf("After inverse sbox: state1 = %016lx, state2 = %016lx\n", state1, state2);
    }
    

    uint64_t final_state[2] = {state1, state2};
    memcpy(plaintext, &final_state, 16); // Copy the final state to plaintext
    return 0; // Return 0 on success
}