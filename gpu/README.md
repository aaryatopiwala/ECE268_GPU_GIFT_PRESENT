## Compilation & Running

Build only:
```bash
./run.sh --build-only
```

Run a cipher target:
```bash
./run.sh --cipher <present|gift> --mode <cbc|ctr>
```

```bash
./run.sh --cipher present --mode cbc
./run.sh --cipher present --mode ctr
./run.sh --cipher gift    --mode cbc
./run.sh --cipher gift    --mode ctr
```

### Profiling & Debugging

Run under `compute-sanitizer` (memory errors, race conditions):
```bash
./run.sh --cipher present --mode cbc --run-mode sanitize
```

Run under `nsys` (generates a `.nsys-rep` report in `build/`):
```bash
./run.sh --cipher present --mode cbc --run-mode profile
```