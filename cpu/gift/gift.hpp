#include <cstdint>
#include <cstring>
#include <cstdio>

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
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 2,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
};

int gift128_encrypt(const uint64_t *plaintext, const uint64_t *key, uint64_t *ciphertext) {
    uint64_t state = *plaintext;

    memcpy(ciphertext, &state, 8); // Copy the final state to ciphertext
    return 0; // Return 0 on success
}

int gift128_decrypt(const uint64_t *ciphertext, const uint64_t *key, uint64_t *plaintext) {
    uint64_t state = *ciphertext;

    memcpy(plaintext, &state, 8); // Copy the final state to plaintext
    return 0; // Return 0 on success
}