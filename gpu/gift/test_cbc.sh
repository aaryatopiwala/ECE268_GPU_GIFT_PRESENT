#!/usr/bin/env bash
set -euo pipefail

# GPU GIFT CBC Mode Tests
# This script tests the GPU implementation of GIFT in CBC mode
# Uses shared test files from the root tests directory
# Usage: ./test_cbc.sh [--profile]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"
GPU_RUN_SCRIPT="$SCRIPT_DIR/gpu/run.sh"
RUNS_DIR="$SCRIPT_DIR/runs"

CIPHER="gift"
MODE="cbc"
RUN_MODE="run"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile) RUN_MODE="profile"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Test vectors with keys and IVs
declare -A TEST_VECTORS=(
    ["beemovie.txt"]="00000000000000000000:0"
    ["moderntimes.mp4"]="00000000000000000000:0"
)

get_plaintext_files() {
    find "$TESTS_DIR" -maxdepth 1 -type f \( -name "*.bin" -o -name "*.txt" -o -name "*.mp4" \) ! -name "*.enc" ! -name "*.dec" | while read file; do
        basename "$file"
    done
}

# Function to measure elapsed time in milliseconds
measure_time() {
    local start_ns=$(date +%s%N)
    "$@"
    local end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    echo "$elapsed_ms"
}

echo "Testing GPU $CIPHER $MODE mode..."

plaintext_files=$(get_plaintext_files)
output_dir="$RUNS_DIR/gpu/$CIPHER/$MODE"
mkdir -p "$output_dir"

# Initialize results file
results_file="$output_dir/results.txt"
echo "GPU $CIPHER $MODE Results" > "$results_file"
echo "=========================" >> "$results_file"
echo "Timestamp: $(date)" >> "$results_file"
echo "" >> "$results_file"

for plaintext_file in $plaintext_files; do
    plaintext_path="$TESTS_DIR/$plaintext_file"
    
    # Get keys and IVs from TEST_VECTORS
    key_iv_pairs="${TEST_VECTORS[$plaintext_file]:-00000000000000000000:0}"
    
    while IFS=: read -r key iv; do
        test_name="${plaintext_file}_key_${key:0:4}_${key: -4}"
        encrypted_file="$output_dir/${test_name}.enc"
        decrypted_file="$output_dir/${test_name}.dec"
        
        # Encrypt
        echo -n "  Encrypting $plaintext_file (key: ${key:0:8}..., iv: $iv)... "
        encrypt_time=$(measure_time "$GPU_RUN_SCRIPT" \
            --cipher "$CIPHER" \
            --mode "$MODE" \
            --run-mode "$RUN_MODE" \
            --encrypt \
            --input "$plaintext_path" \
            --key "$key" \
            --iv "$iv" \
            --output "$encrypted_file" 2>/dev/null) || {
            echo "FAILED"
            echo "$test_name (encrypt): FAILED" >> "$results_file"
            continue
        }
        echo "OK (${encrypt_time}ms)"
        
        # Decrypt
        echo -n "  Decrypting encrypted $plaintext_file... "
        decrypt_time=$(measure_time "$GPU_RUN_SCRIPT" \
            --cipher "$CIPHER" \
            --mode "$MODE" \
            --run-mode "$RUN_MODE" \
            --decrypt \
            --input "$encrypted_file" \
            --key "$key" \
            --iv "$iv" \
            --output "$decrypted_file" 2>/dev/null) || {
            echo "FAILED"
            echo "$test_name (decrypt): FAILED" >> "$results_file"
            continue
        }
        echo "OK (${decrypt_time}ms)"
        
        # Verify decrypted matches original
        echo -n "  Verifying decrypted matches original... "
        if cmp -s "$decrypted_file" "$plaintext_path"; then
            echo "PASS"
            echo "$test_name: PASS (encrypt: ${encrypt_time}ms, decrypt: ${decrypt_time}ms)" >> "$results_file"
        else
            echo "FAIL"
            echo "$test_name: FAIL (size mismatch)" >> "$results_file"
        fi
    done <<< "$key_iv_pairs"
done

echo "" >> "$results_file"
echo "Test completed at $(date)" >> "$results_file"
