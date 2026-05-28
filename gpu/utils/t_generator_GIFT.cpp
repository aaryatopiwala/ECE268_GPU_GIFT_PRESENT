#include <iostream>
#include <fstream>
#include <cstdint>
#include <iomanip>

struct Gift128Block {
    uint64_t lo;
    uint64_t hi;
};

const uint8_t sbox[16] = {
    0x1, 0xa, 0x4, 0xc,
    0x6, 0xf, 0x3, 0x9,
    0x2, 0xd, 0xb, 0x7,
    0x5, 0x0, 0x8, 0xe
};

int gift128_perm_index(int i) {
    int imod16 = i & 15;
    int imod4  = i & 3;

    return 4 * (i >> 4)
         + 32 * ((3 * (imod16 >> 2) + imod4) & 3)
         + imod4;
}

void set_bit(Gift128Block& x, int pos) {
    if (pos < 64)
        x.lo |= (1ULL << pos);
    else
        x.hi |= (1ULL << (pos - 64));
}

int main() {
    Gift128Block T_tables[32][16] = {};

    for (int n = 0; n < 32; n++) {
        for (int v = 0; v < 16; v++) {
            Gift128Block out = {0, 0};

            uint8_t s_val = sbox[v];

            for (int b = 0; b < 4; b++) {
                if ((s_val >> b) & 1) {
                    int orig_pos = 4 * n + b;
                    int new_pos = gift128_perm_index(orig_pos);
                    set_bit(out, new_pos);
                }
            }

            T_tables[n][v] = out;
        }
    }

    std::ofstream outfile("gift128_t_tables.cuh");
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not open file for writing!\n";
        return 1;
    }

    outfile << "#pragma once\n\n";
    outfile << "static __constant__ Gift128Block d_gift128_T[32][16] = {\n";

    for (int n = 0; n < 32; n++) {
        outfile << "    {\n";

        for (int v = 0; v < 16; v++) {
            outfile << "        { "
                    << "0x" << std::hex << std::setw(16) << std::setfill('0') << T_tables[n][v].lo << "ULL, "
                    << "0x" << std::hex << std::setw(16) << std::setfill('0') << T_tables[n][v].hi << "ULL"
                    << " }";

            if (v < 15)
                outfile << ",";

            outfile << "\n";
        }

        outfile << "    }";

        if (n < 31)
            outfile << ",";

        outfile << "\n";
    }

    outfile << "};\n";
    outfile.close();

    return 0;
}