#include <iostream>
#include <fstream>
#include <cstdint>
#include <iomanip>

const uint8_t sbox[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

const uint8_t p_layer[64] = {
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

int main() {
    uint64_t T_tables[16][16] = {0};

    // Loop through all 16 nibble positions
    for (int t = 0; t < 16; t++) {
        // Loop through all 16 possible 4-bit input values
        for (int v = 0; v < 16; v++) {
            uint8_t s_val = sbox[v];
            uint64_t enc_entry = 0;
            
            for (int b = 0; b < 4; b++) {
                if ((s_val >> b) & 1) {
                    int orig_pos = (t * 4) + b;
                    int new_pos = p_layer[orig_pos];
                    enc_entry |= (1ULL << new_pos);
                }
            }
            T_tables[t][v] = enc_entry;
        }
    }

    std::ofstream outfile("t_tables.cuh");
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not open file for writing!\n";
        return 1;
    }
    outfile << "__constant__ uint64_t d_T[16][16] = {\n";
    for (int t = 0; t < 16; t++) {
        outfile << "    { ";
        for (int v = 0; v < 16; v++) {
            outfile << std::dec << T_tables[t][v] << "ULL";
            if (v < 15) outfile << ", ";
        }
        outfile << " }";
        if (t < 15) outfile << ",\n";
        else outfile << "\n";
    }
    outfile << "};\n";
    outfile.close();

    return 0;
}