// Counter (CTR) with AES-128
#include "aes.cuh"
#include <cstdio>
#include <cstdlib>
#include <string.h>

#define BUFFER_SIZE (8 * 1024 * 1024)

static void encrypt_ctr_buffer(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const uint64_t *key, uint64_t *counter) {
    for (size_t i = 0; i < length; i += 16) {
        // gift is 128 bit plaintext block
        uint64_t block1 = ((uint64_t)plaintext[i] << 56) | ((uint64_t)plaintext[i+1] << 48) |
                ((uint64_t)plaintext[i+2] << 40) | ((uint64_t)plaintext[i+3] << 32) |
                ((uint64_t)plaintext[i+4] << 24) | ((uint64_t)plaintext[i+5] << 16) |
                ((uint64_t)plaintext[i+6] << 8)  | ((uint64_t)plaintext[i+7] << 0);

        uint64_t block2 = ((uint64_t)plaintext[i+8] << 56) | ((uint64_t)plaintext[i+9] << 48) |
                ((uint64_t)plaintext[i+10] << 40) | ((uint64_t)plaintext[i+11] << 32) |
                ((uint64_t)plaintext[i+12] << 24) | ((uint64_t)plaintext[i+13] << 16) |
                ((uint64_t)plaintext[i+14] << 8)  | ((uint64_t)plaintext[i+15] << 0);

        block1 = counter[0];
        block2 = counter[1];
        uint64_t block[2] = {block1, block2};
        uint64_t cipher_block[2];
        uint64_t cipher_block1, cipher_block2;
        //printf("Plain block: %016lx %016lx\n", block[0], block[1]);
        //printf("Key: %016lx %016lx\n", key[0], key[1]);
        //printf("Prev cipher: %016lx %016lx\n", prev_cipher[0], prev_cipher[1]);
        aes128_encrypt(block, key, cipher_block);

        ciphertext[i+0] = ((cipher_block[0] >> 56) & 0xFF) ^ plaintext[i];
        ciphertext[i+1] = ((cipher_block[0] >> 48) & 0xFF) ^ plaintext[i+1];
        ciphertext[i+2] = ((cipher_block[0] >> 40) & 0xFF) ^ plaintext[i+2];
        ciphertext[i+3] = ((cipher_block[0] >> 32) & 0xFF) ^ plaintext[i+3];
        ciphertext[i+4] = ((cipher_block[0] >> 24) & 0xFF) ^ plaintext[i+4];
        ciphertext[i+5] = ((cipher_block[0] >> 16) & 0xFF) ^ plaintext[i+5];
        ciphertext[i+6] = ((cipher_block[0] >> 8) & 0xFF) ^ plaintext[i+6];
        ciphertext[i+7] = ((cipher_block[0] >> 0) & 0xFF) ^ plaintext[i+7];

        ciphertext[i+8] = ((cipher_block[1] >> 56) & 0xFF) ^ plaintext[i+8];
        ciphertext[i+9] = ((cipher_block[1] >> 48) & 0xFF) ^ plaintext[i+9];
        ciphertext[i+10] = ((cipher_block[1] >> 40) & 0xFF) ^ plaintext[i+10];
        ciphertext[i+11] = ((cipher_block[1] >> 32) & 0xFF) ^ plaintext[i+11];
        ciphertext[i+12] = ((cipher_block[1] >> 24) & 0xFF) ^ plaintext[i+12];
        ciphertext[i+13] = ((cipher_block[1] >> 16) & 0xFF) ^ plaintext[i+13];
        ciphertext[i+14] = ((cipher_block[1] >> 8) & 0xFF) ^ plaintext[i+14];
        ciphertext[i+15] = ((cipher_block[1] >> 0) & 0xFF) ^ plaintext[i+15];
    }
}

void hex_to_key(const char *hex_str, uint64_t *key) {
    uint64_t hex_len = strlen(hex_str);
    uint8_t key_bytes[16] = {0};
    for (int i = 0; i < 16 && 2*i < hex_len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &key_bytes[i]);
    }
    key[0] = 0;
    key[1] = 0;
    key[0] = ((uint64_t)key_bytes[7] << 0) | ((uint64_t)key_bytes[6] << 8) | ((uint64_t)key_bytes[5] << 16) | ((uint64_t)key_bytes[4] << 24) |
              ((uint64_t)key_bytes[3] << 32) | ((uint64_t)key_bytes[2] << 40) | ((uint64_t)key_bytes[1] << 48) | ((uint64_t)key_bytes[0] << 56);
    key[1] = ((uint64_t)key_bytes[15] << 0) | ((uint64_t)key_bytes[14] << 8) | ((uint64_t)key_bytes[13] << 16) | ((uint64_t)key_bytes[12] << 24) |
              ((uint64_t)key_bytes[11] << 32) | ((uint64_t)key_bytes[10] << 40) | ((uint64_t)key_bytes[9] << 48) | ((uint64_t)key_bytes[8] << 56);
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

    uint64_t key[2] = {0, 0};
    hex_to_key(argv[3], key);
    uint64_t iv[2] = {0, 0};
    hex_to_key(argv[4], iv);
    //uint64_t iv = (uint64_t)strtoul(argv[4], NULL, 16);

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

        uint64_t *prev_cipher = iv;
        //printf("IV: %016lx %016lx, KEY: %016lx %016lx\n", iv[0], iv[1], key[0], key[1]);
        size_t total_processed = 0;

        // streaming since can't malloc everything at once
        uint64_t counter0 = 0;
        uint64_t counter1 = 0;
        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(plaintext, 1, to_read, input_file);

            if (bytes_read == 0) break;

            size_t process_size = bytes_read;
            bool is_last = (total_processed + bytes_read >= total_size);

            // Apply PKCS7 padding only to last chunk if not --nopad
            if (is_last && !no_pad) {
                size_t pad_len = 16 - (bytes_read % 16);
                memset(plaintext + bytes_read, pad_len, pad_len);
                process_size = bytes_read + pad_len;
            }

            uint64_t counter[2] = {counter0, counter1};
            encrypt_ctr_buffer(plaintext, ciphertext, process_size, key, counter);

            fwrite(ciphertext, 1, process_size, output_file);
            total_processed += bytes_read;
            counter0++;
            if (counter0 == 0) {
                counter1++;
            }
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

        uint64_t *prev_cipher = iv;
        size_t total_processed = 0;

        uint64_t counter0 = 0;
        uint64_t counter1 = 0;
        while (total_processed < total_size) {
            size_t to_read = (total_size - total_processed > BUFFER_SIZE) ? BUFFER_SIZE : (total_size - total_processed);
            size_t bytes_read = fread(ciphertext, 1, to_read, input_file);

            if (bytes_read == 0) break;

            bool is_last = (total_processed + bytes_read >= total_size);

            //printf("prev_cipher: %016lx %016lx\n; key: %016lx %016lx\n ", prev_cipher[0], prev_cipher[1], key[0], key[1]);
            // ctr mode uses encrypt for decrypt
            uint64_t counter[2] = {counter0, counter1};
            encrypt_ctr_buffer(ciphertext, plaintext, bytes_read, key, counter);

            size_t write_size = bytes_read;

            // Remove PKCS7 padding only from last chunk if not --nopad
            if (is_last && !no_pad) {
                uint8_t pad_len = plaintext[bytes_read - 1];
                if (pad_len > 0 && pad_len <= 16) {
                    write_size = bytes_read - pad_len;
                } else if (pad_len == 0) {
                    write_size = bytes_read - 16;
                }
            }

            fwrite(plaintext, 1, write_size, output_file);
            total_processed += bytes_read;
            counter0++;
            if (counter0 == 0) {
                counter1++;
            }
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
