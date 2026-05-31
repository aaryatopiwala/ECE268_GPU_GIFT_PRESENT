#!/usr/bin/env python3

# Usage: 
# ./gen_test_file.py output --mb x
# ./gen_test_file.py output --kb x
# ./gen_test_file.py output --gb x
# ./gen_test_file.py output --b x

import argparse
from pathlib import Path

def generate_file(path: Path, total_bytes: int):
    chunk_size = 1024 * 1024
    
    if total_bytes < chunk_size:
        chunk_size = total_bytes if total_bytes > 0 else 1

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

    print(f"Generated {path} ({total_bytes} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Generate a test file with a pseudo-random pattern.")
    parser.add_argument("output", help="output file path")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--b", type=int, help="file size in Bytes")
    group.add_argument("--kb", type=int, help="file size in KB")
    group.add_argument("--mb", type=int, help="file size in MB")
    group.add_argument("--gb", type=int, help="file size in GB")
    
    args = parser.parse_args()

    # Calculate total bytes based on the provided flag
    if args.b is not None:
        total_bytes = args.b
    elif args.kb is not None:
        total_bytes = args.kb * 1024
    elif args.gb is not None:
        total_bytes = args.gb * 1024 * 1024 * 1024
    elif args.mb is not None:
        total_bytes = args.mb * 1024 * 1024
    else:
        # Default behavior: 128 MB if no size argument is provided
        total_bytes = 128 * 1024 * 1024

    generate_file(Path(args.output), total_bytes)

if __name__ == "__main__":
    main()