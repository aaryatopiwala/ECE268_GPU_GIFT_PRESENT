// Cipher Block Chaining (CBC) with Present
#include "present.hpp"
#include <cstdio>
#include <cstdlib>
#include <string.h>

#define BUFFER_SIZE (8 * 1024 * 1024)

static void encrypt_cbc_buffer(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const uint64_t *key, uint64_t *prev_cipher) {
    for (size_t i = 0; i < length; i += 8) {
        uint64_t block = ((uint64_t)plaintext[i] << 56) | ((uint64_t)plaintext[i+1] << 48) |
                        ((uint64_t)plaintext[i+2] << 40) | ((uint64_t)plaintext[i+3] << 32) |
                        ((uint64_t)plaintext[i+4] << 24) | ((uint64_t)plaintext[i+5] << 16) |
                        ((uint64_t)plaintext[i+6] << 8) | (uint64_t)plaintext[i+7];

        block = block ^ *prev_cipher;
        uint64_t cipher_block;
        present80_encrypt(&block, key, &cipher_block);

        ciphertext[i] = (cipher_block >> 56) & 0xFF;
        ciphertext[i+1] = (cipher_block >> 48) & 0xFF;
        ciphertext[i+2] = (cipher_block >> 40) & 0xFF;
        ciphertext[i+3] = (cipher_block >> 32) & 0xFF;
        ciphertext[i+4] = (cipher_block >> 24) & 0xFF;
        ciphertext[i+5] = (cipher_block >> 16) & 0xFF;
        ciphertext[i+6] = (cipher_block >> 8) & 0xFF;
        ciphertext[i+7] = (cipher_block & 0xFF);

        *prev_cipher = cipher_block;
    }
}

static void decrypt_cbc_buffer(const uint8_t *ciphertext, uint8_t *plaintext, size_t length, const uint64_t *key, uint64_t *prev_cipher) {
    for (size_t i = 0; i < length; i += 8) {
        uint64_t cipher_block = ((uint64_t)ciphertext[i] << 56) | ((uint64_t)ciphertext[i+1] << 48) |
                               ((uint64_t)ciphertext[i+2] << 40) | ((uint64_t)ciphertext[i+3] << 32) |
                               ((uint64_t)ciphertext[i+4] << 24) | ((uint64_t)ciphertext[i+5] << 16) |
                               ((uint64_t)ciphertext[i+6] << 8) | (uint64_t)ciphertext[i+7];

        uint64_t block;
        present80_decrypt(&cipher_block, key, &block);

        plaintext[i] = (uint8_t)((block ^ *prev_cipher) >> 56);
        plaintext[i+1] = (uint8_t)((block ^ *prev_cipher) >> 48);
        plaintext[i+2] = (uint8_t)((block ^ *prev_cipher) >> 40);
        plaintext[i+3] = (uint8_t)((block ^ *prev_cipher) >> 32);
        plaintext[i+4] = (uint8_t)((block ^ *prev_cipher) >> 24);
        plaintext[i+5] = (uint8_t)((block ^ *prev_cipher) >> 16);
        plaintext[i+6] = (uint8_t)((block ^ *prev_cipher) >> 8);
        plaintext[i+7] = (uint8_t)((block ^ *prev_cipher) & 0xFF);

        *prev_cipher = cipher_block;
    }
}

void hex_to_key(const char *hex_str, uint64_t *key) {
    uint8_t key_bytes[10] = {0};
    for (int i = 0; i < 10; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &key_bytes[i]);
    }
    key[0] = 0;
    key[1] = 0;
    key[0] = ((uint64_t)key_bytes[0] << 56) | ((uint64_t)key_bytes[1] << 48) | ((uint64_t)key_bytes[2] << 40) | ((uint64_t)key_bytes[3] << 32) |
              ((uint64_t)key_bytes[4] << 24) | ((uint64_t)key_bytes[5] << 16) | ((uint64_t)key_bytes[6] << 8) | (uint64_t)key_bytes[7];
    key[1] = ((uint64_t)key_bytes[8] << 8) | (uint64_t)key_bytes[9];
}

int main(int argc, char *argv[]) {
    // -e for encryption, -d for decryption
    // key and iv are provided as hexadecimal strings
    // ./present_cbc -e plaintext.txt "key" "iv" ciphertext.bin --nopad
    // ./present_cbc -d ciphertext.txt "key" "iv" decrypted.txt --nopad
    // --nopad for no padding, useful for test vectors.
    int no_pad = 0;
    if (argc == 7 && strcmp(argv[6], "--nopad") == 0) {
        no_pad = 1;
    }

    if (argc != 6 && argc != 7) {
        fprintf(stderr, "Usage: %s -e|-d <input_file> <key> <iv> <output_file>\n", argv[0]);
        return 1;
    }

    FILE *input_file = fopen(argv[2], "rb");
    if (!input_file) {
        perror("Failed to open input file");
        return 1;
    }

    fseek(input_file, 0, SEEK_END);
    size_t total_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    uint64_t key[2];
    hex_to_key(argv[3], key);
    uint64_t iv = (uint64_t)strtoul(argv[4], NULL, 16);

    FILE *output_file = fopen(argv[5], "wb");
    if (!output_file) {
        perror("Failed to open output file");
        fclose(input_file);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        uint8_t *plaintext = (uint8_t *)malloc(BUFFER_SIZE + 8);
        uint8_t *ciphertext = (uint8_t *)malloc(BUFFER_SIZE + 8);

        if (!plaintext || !ciphertext) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(input_file);
            fclose(output_file);
            return 1;
        }

        uint64_t prev_cipher = iv;
        size_t total_processed = 0;

        // streaming since can't malloc everything at once
        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(plaintext, 1, to_read, input_file);

            if (bytes_read == 0) break;

            size_t process_size = bytes_read;
            bool is_last = (total_processed + bytes_read >= total_size);

            // Apply PKCS7 padding only to last chunk if not --nopad
            if (is_last && !no_pad) {
                size_t pad_len = 8 - (bytes_read % 8);
                memset(plaintext + bytes_read, pad_len, pad_len);
                process_size = bytes_read + pad_len;
            }

            encrypt_cbc_buffer(plaintext, ciphertext, process_size, key, &prev_cipher);

            fwrite(ciphertext, 1, process_size, output_file);
            total_processed += bytes_read;
        }

        free(plaintext);
        free(ciphertext);

    } else if (strcmp(argv[1], "-d") == 0) {
        uint8_t *ciphertext = (uint8_t *)malloc(BUFFER_SIZE);
        uint8_t *plaintext = (uint8_t *)malloc(BUFFER_SIZE);

        if (!ciphertext || !plaintext) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(input_file);
            fclose(output_file);
            return 1;
        }

        uint64_t prev_cipher = iv;
        size_t total_processed = 0;

        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(ciphertext, 1, to_read, input_file);

            if (bytes_read == 0) break;

            bool is_last = (total_processed + bytes_read >= total_size);

            decrypt_cbc_buffer(ciphertext, plaintext, bytes_read, key, &prev_cipher);

            size_t write_size = bytes_read;

            // Remove PKCS7 padding only from last chunk if not --nopad
            if (is_last && !no_pad) {
                uint8_t pad_len = plaintext[bytes_read - 1];
                if (pad_len > 0 && pad_len <= 8) {
                    write_size = bytes_read - pad_len;
                } else if (pad_len == 0) {
                    write_size = bytes_read - 8;
                }
            }

            fwrite(plaintext, 1, write_size, output_file);
            total_processed += bytes_read;
        }

        free(ciphertext);
        free(plaintext);

    } else {
        fprintf(stderr, "Invalid option: %s\n", argv[1]);
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    fclose(input_file);
    fclose(output_file);
    return 0;
}
