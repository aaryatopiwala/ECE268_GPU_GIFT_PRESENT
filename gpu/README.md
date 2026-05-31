# Lightweight Block Cipher GPU Implementations

This directory contains the CUDA-accelerated implementations of the PRESENT, GIFT, and AES block ciphers.

## Compilation & Running

### Building the Targets

To manually build the GPU targets, create a build directory and use CMake:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
```

### Running Ciphers Directly

Once compiled, you can run a specific cipher target directly from the build/ directory:

```bash
# CBC Mode
./present_cbc -e plain.txt <key> <iv> cipher.bin
./present_cbc -d cipher.bin <key> <iv> plain.txt

# CTR Mode (Requires the --nopad flag)
./present_ctr -e plain.txt <key> <iv> cipher.bin --nopad
./present_ctr    -d cipher.bin <key> <iv> plain.txt --nopad
```

---

## Test Runner

This directory includes a comprehensive test runner (`run_gpu.sh`) that automates building, static analysis (PTX/CUBIN metrics, Lines of Code), correctness verification, and throughput benchmarking across all ciphers, modes, and test vectors.

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

`--profile`
    Run Nsight Systems (nsys) to collect and parse host APIs, kernel executions, and memory transfer (H2D/D2H) metrics.

`--static-only`
    Skip actual encryption/decryption tests and only generate source, PTX, and CUBIN metrics.

`--no-static`
    Skip source, PTX, and CUBIN static analysis and only run the encryption/decryption tests.

`--clean`
    Remove the build directory to force a fresh compilation before running.

`--help, -h`
    Show the help message and exit.

### Usage Examples

Run the entire test suite (all ciphers, modes, and static analysis):
```bash
./run_tests.sh --clean
```

Run a specific cipher and mode, skipping static analysis:
```bash
./run_tests.sh --cipher present --mode ctr --no-static
```

Run AES-CBC with Nsight Systems profiling enabled:
```bash
./run_tests.sh --cipher aes --mode cbc --profile
```

Test a specific file against all pre-configured keysets:
```bash
./run_tests.sh --file moderntimes.mp4 --keyset all
``` 

Test with a custom Key and IV override:
```bash
./run_tests.sh --cipher gift --mode ctr --key 0123456789abcdef0123 --iv 0000000000000000
```