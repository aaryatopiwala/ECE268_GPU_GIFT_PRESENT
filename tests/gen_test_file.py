#!/usr/bin/env python3

#Usage gen_test_file.py output --mb x

import argparse
from pathlib import Path

def generate_file(path: Path, size_mb: int):
    total_bytes = size_mb * 1024 * 1024
    chunk_size = 1024 * 1024
    
    pattern = bytearray(chunk_size)
    x = 0x12345678

    with path.open("wb") as f:
        written = 0

        while written < total_bytes:
            n = min(chunk_size, total_bytes - written)

            for i in range(n):
                x ^= (x << 13) & 0xffffffff
                x ^= (x >> 17)
                x ^= (x << 5) & 0xffffffff
                pattern[i] = x & 0xff

            f.write(pattern[:n])
            written += n

    print(f"Generated {path} ({total_bytes} bytes, {size_mb} MB)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", help="output file path")
    parser.add_argument("--mb", type=int, default=128, help="file size in MB")
    args = parser.parse_args()

    generate_file(Path(args.output), args.mb)

if __name__ == "__main__":
    main()