#!/usr/bin/env bash
set -euo pipefail

# GPU PRESENT CTR Mode Tests
# This script tests the GPU implementation of PRESENT in CTR mode
# Uses shared test files from the root tests directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"
GPU_RUN_SCRIPT="$SCRIPT_DIR/gpu/run.sh"
RUNS_DIR="$SCRIPT_DIR/runs"

CIPHER="present"
MODE="ctr"

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

echo "Testing GPU $CIPHER $MODE mode..."

plaintext_files=$(get_plaintext_files)

for plaintext_file in $plaintext_files; do
    plaintext_path="$TESTS_DIR/$plaintext_file"
    
    # Get keys and IVs from TEST_VECTORS
    key_iv_pairs="${TEST_VECTORS[$plaintext_file]:-00000000000000000000:0}"
    
    # Create output directory
    output_dir="$RUNS_DIR/gpu/$CIPHER/$MODE"
    mkdir -p "$output_dir"
    
    while IFS=: read -r key iv; do
        test_name="${plaintext_file}_key_${key:0:4}_${key: -4}"
        encrypted_file="$output_dir/${test_name}.enc"
        decrypted_file="$output_dir/${test_name}.dec"
        
        # Encrypt
        echo -n "  Encrypting $plaintext_file (key: ${key:0:8}..., iv: $iv)... "
        if "$GPU_RUN_SCRIPT" \
            --cipher "$CIPHER" \
            --mode "$MODE" \
            --encrypt \
            --input "$plaintext_path" \
            --key "$key" \
            --iv "$iv" \
            --output "$encrypted_file" \
            --nopad 2>/dev/null; then
            echo "OK"
        else
            echo "FAILED"
            continue
        fi
        
        # Decrypt
        echo -n "  Decrypting encrypted $plaintext_file... "
        if "$GPU_RUN_SCRIPT" \
            --cipher "$CIPHER" \
            --mode "$MODE" \
            --decrypt \
            --input "$encrypted_file" \
            --key "$key" \
            --iv "$iv" \
            --output "$decrypted_file" \
            --nopad 2>/dev/null; then
            echo "OK"
        else
            echo "FAILED"
            continue
        fi
        
        # Verify decrypted matches original
        echo -n "  Verifying decrypted matches original... "
        if cmp -s "$decrypted_file" "$plaintext_path"; then
            echo "PASS"
        else
            echo "FAIL"
            echo "    File size mismatch: original=$(stat -f%z "$plaintext_path") decrypted=$(stat -f%z "$decrypted_file")"
        fi
    done <<< "$key_iv_pairs"
done
