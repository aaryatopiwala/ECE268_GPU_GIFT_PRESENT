## Compilation & Running

Build only:
```bash
./run.sh --build-only
```

Run a cipher target:
```bash
./run.sh --cipher <present|gift> --mode <cbc|ctr> --encrypt|--decrypt --input <file> --key <hex> --iv <hex> --output <file> [--nopad]
```

```bash
./run.sh --cipher present --mode cbc --encrypt --input plain.txt    --key <hex> --iv <hex> --output cipher.bin
./run.sh --cipher present --mode cbc --decrypt --input cipher.bin   --key <hex> --iv <hex> --output plain.txt
./run.sh --cipher present --mode ctr --encrypt --input plain.txt    --key <hex> --iv <hex> --output cipher.bin
./run.sh --cipher gift    --mode cbc --encrypt --input plain.txt    --key <hex> --iv <hex> --output cipher.bin
./run.sh --cipher gift    --mode ctr --decrypt --input cipher.bin   --key <hex> --iv <hex> --output plain.txt
```

### Profiling & Debugging

Run under `nsys` (generates a `.nsys-rep` report in `build/`):
```bash
./run.sh --cipher present --mode cbc --encrypt --input plain.txt --key <hex> --iv <hex> --output cipher.bin --run-mode profile
```

Run under `compute-sanitizer` (memory errors, race conditions) — requires CUDA 11+ and SM 7.5+:
```bash
./run.sh --cipher present --mode cbc --encrypt --input plain.txt --key <hex> --iv <hex> --output cipher.bin --run-mode sanitize
```