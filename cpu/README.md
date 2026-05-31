# Lightweight Block Cipher CPU Implementations

This directory contains the CPU-based C++ implementations of the PRESENT, GIFT, and AES block ciphers.

## Compilation & Running

### Building the Targets

To manually build the CPU targets, create a build directory and use CMake:

```bash
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

### Running Ciphers Directly

Once compiled, you can run a specific cipher target directly from its directory:

```bash
# PRESENT CBC Mode
./build/present_cbc -e plain.txt <key> <iv> cipher.bin
./build/present_cbc -d cipher.bin <key> <iv> plain.txt

# PRESENT CTR Mode (Requires the --nopad flag)
./build/present_ctr -e plain.txt <key> <iv> cipher.bin --nopad
./build/present_ctr -d cipher.bin <key> <iv> plain.txt --nopad

# GIFT CBC Mode
./build/gift_cbc -e plain.txt <key> <iv> cipher.bin
./build/gift_cbc -d cipher.bin <key> <iv> plain.txt

# GIFT CTR Mode (Requires the --nopad flag)
./build/gift_ctr -e plain.txt <key> <iv> cipher.bin --nopad
./build/gift_ctr -d cipher.bin <key> <iv> plain.txt --nopad

# AES CBC Mode
./build/aes_cbc -e plain.txt <key> <iv> cipher.bin
./build/aes_cbc -d cipher.bin <key> <iv> plain.txt

# AES CTR Mode (Requires the --nopad flag)
./build/aes_ctr -e plain.txt <key> <iv> cipher.bin --nopad
./build/aes_ctr -d cipher.bin <key> <iv> plain.txt --nopad
```

---

## Test Runner

This directory includes a comprehensive test runner (`run_cpu.sh`) that automates building, correctness verification, and throughput benchmarking across all ciphers, modes, and test vectors. 

Note: Because this is the CPU environment, GPU-specific static analysis and Nsight Systems profiling are not implemented, though the flags are accepted for cross-compatibility with the GPU runner.

### Available Flags

`--cipher <present|gift|aes|all>`
    Specify the target cipher algorithm (Default: all).

`--mode <ctr|cbc|all>`
    Specify the block cipher mode of operation (Default: all).

`--file <filename>`
    Target tests against a single specified plaintext file.

`--keyset <zero|inc|ff|all>`
    Select built-in key/IV vector set (Default: inc).

`--key <hex>`
    Override the default encryption key with a custom hex string.

`--iv <hex>`
    Override the default initialization vector with a custom hex string.

`--clean`
    Run `make clean` before building each CPU target to force a fresh compilation.

`--profile`
    Accepted for compatibility (Outputs timing summaries only; CPU does not use `nsys`).

`--static-only`
    Accepted for compatibility (Skips all tests; CPU static analysis is not implemented).

`--no-static`
    Accepted for compatibility.

`--help`, `-h`
    Show the help message and exit.

### Usage Examples

Run the entire test suite (all ciphers and modes):
```bash
./run_cpu.sh
```

Run a specific cipher and mode on a fresh build:
```bash
./run_cpu.sh --cipher present --mode ctr --clean
```

Test a specific file against all pre-configured keysets:
```bash
./run_cpu.sh --file moderntimes.mp4 --keyset all
```

Test with a custom Key and IV override:
```bash
./run_cpu.sh --cipher gift --mode ctr --key 0123456789abcdef0123 --iv 0000000000000000
```