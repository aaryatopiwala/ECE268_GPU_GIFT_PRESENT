#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNS_DIR="$REPO_DIR/runs"

echo "=========================================="
echo "Running Cipher Tests"
echo "=========================================="
echo "Results stored in: $RUNS_DIR/"
echo ""

# Define which ciphers and modes to test
# Format: "cipher:mode cpu/gpu"
declare -a TESTS=(
    # PRESENT Tests
    "present:ctr:gpu"
    # "present:cbc:gpu"
    # "present:ctr:cpu"
    # "present:cbc:cpu"
    
    # GIFT Tests (commented out for future implementation)
    # "gift:ctr:gpu"
    # "gift:cbc:gpu"
    # "gift:ctr:cpu"
    # "gift:cbc:cpu"
    
    # AES Tests (commented out for future implementation)
    # "aes:ctr:gpu"
    # "aes:cbc:gpu"
    # "aes:ctr:cpu"
    # "aes:cbc:cpu"
)

# Run each test
for test in "${TESTS[@]}"; do
    IFS=: read -r cipher mode platform <<< "$test"
    
    if [ -z "$cipher" ] || [ -z "$mode" ] || [ -z "$platform" ]; then
        continue
    fi
    
    test_script="$REPO_DIR/$platform/$cipher/test_${mode}.sh"
    
    if [ ! -f "$test_script" ]; then
        echo "WARNING: Test script not found: $test_script"
        continue
    fi
    
    echo ""
    echo "=========================================="
    echo "Running ${platform^^} $cipher $mode tests"
    echo "=========================================="
    
    bash "$test_script"
done

echo ""
echo "=========================================="
echo "All tests completed!"
echo "Results stored in: $RUNS_DIR/"
echo "=========================================="
