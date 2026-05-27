## Compilation & Running

Build the GPU targets:
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
```

Run a cipher target directly from `build/`:
```bash
./present_cbc -e plain.txt <key> <iv> cipher.bin
./present_cbc -d cipher.bin <key> <iv> plain.txt
./present_ctr -e plain.txt <key> <iv> cipher.bin --nopad
./gift_cbc    -e plain.txt <key> <iv> cipher.bin
./gift_ctr    -d cipher.bin <key> <iv> plain.txt --nopad
```

### Running tests

Use the unified GPU test runner:
```bash
./run_tests.sh --cipher present --mode ctr
```

### Profiling

Use the GPU test runner with profiling enabled:
```bash
./run_tests.sh --cipher present --mode cbc --profile
```

### Notes

- AES GPU implementation is not available yet; `--cipher aes` will be skipped by the GPU test harness.
