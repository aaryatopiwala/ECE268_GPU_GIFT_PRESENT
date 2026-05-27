#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$REPO_DIR/../tests"
RUNS_DIR="$REPO_DIR/../runs"
BUILD_DIR="$REPO_DIR/build"

SUPPORTED_CIPHERS=(present gift aes)
SUPPORTED_MODES=(ctr cbc)

declare -A DEFAULT_KEY_IV
DEFAULT_KEY_IV=(
    ["beemovie.txt"]="00000000000000000000:0"
    ["moderntimes.mp4"]="00000000000000000000:0"
)

SELECT_CIPHER="all"
SELECT_MODE="all"
OVERRIDE_KEY=""
OVERRIDE_IV=""
PROFILE=false

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --cipher <present|gift|aes|all>   Select cipher to test (default: all)
  --mode <ctr|cbc|all>              Select mode to test (default: all)
  --key <hex>                       Override default key for all test files
  --iv <hex>                        Override default IV for all test files
  --profile                         Enable nsys GPU profiling for each run
  --help                            Show this help message

Note: AES GPU implementation is not available yet; AES tests will be skipped.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cipher)
            SELECT_CIPHER="${2,,}"
            shift 2
            ;;
        --mode)
            SELECT_MODE="${2,,}"
            shift 2
            ;;
        --key)
            OVERRIDE_KEY="$2"
            shift 2
            ;;
        --iv)
            OVERRIDE_IV="$2"
            shift 2
            ;;
        --profile)
            PROFILE=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

get_plaintext_files() {
    find "$TESTS_DIR" -maxdepth 1 -type f \( -name "*.bin" -o -name "*.txt" -o -name "*.mp4" \) ! -name "*de.*" | sort
}

should_test_cipher() {
    local cipher="$1"
    if [ "$SELECT_CIPHER" = "all" ]; then
        return 0
    fi
    [ "$cipher" = "$SELECT_CIPHER" ]
}

should_test_mode() {
    local mode="$1"
    if [ "$SELECT_MODE" = "all" ]; then
        return 0
    fi
    [ "$mode" = "$SELECT_MODE" ]
}

is_gpu_cipher_supported() {
    local cipher="$1"
    case "$cipher" in
        aes)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

num_cpus() {
    getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1
}

build_target() {
    local target="$1"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$REPO_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null
    make -j"$(num_cpus)" "$target" >/dev/null
}

time_command() {
    local start_ns end_ns status
    start_ns=$(date +%s%N)
    
    "$@" >/dev/null 2>&1
    status=$?
    set -e
    
    end_ns=$(date +%s%N)
    printf "%s %s" "$status" "$(( (end_ns - start_ns) / 1000000 ))"
}

run_test() {
    local cipher="$1"
    local mode="$2"
    local run_mode="run"
    if [ "$PROFILE" = true ]; then
        run_mode="profile"
    fi

    echo ""
    echo "GPU $cipher $mode tests"

    local target="${cipher}_${mode}"
    if ! build_target "$target"; then
        echo "ERROR: Failed to build GPU $cipher $mode" >&2
        return 1
    fi

    local output_dir="$RUNS_DIR/gpu/$cipher/$mode"
    mkdir -p "$output_dir"
    local results_file="$output_dir/results.txt"

    printf "GPU %s %s Results\n" "$cipher" "$mode" > "$results_file"
    printf "%s\n" "" >> "$results_file"
    printf "Timestamp: %s\n\n" "$(date)" >> "$results_file"

    for plaintext_path in $(get_plaintext_files); do
        local plaintext_file
        plaintext_file=$(basename "$plaintext_path")
        local key_iv
        if [ -n "$OVERRIDE_KEY" ] || [ -n "$OVERRIDE_IV" ]; then
            key_iv="${OVERRIDE_KEY:-00000000000000000000}:${OVERRIDE_IV:-0}"
        else
            key_iv="${DEFAULT_KEY_IV[$plaintext_file]:-00000000000000000000:0}"
        fi

        local key iv
        IFS=':' read -r key iv <<< "$key_iv"
        local test_name="${plaintext_file}_key_${key:0:4}_${key: -4}"
        local encrypted_file="$output_dir/${test_name}.enc"
        local decrypted_file="$output_dir/${test_name}.dec"

        local cmd=("$BUILD_DIR/$target" "-e" "$plaintext_path" "$key" "$iv" "$encrypted_file")
        if [ "$mode" = "ctr" ]; then
            cmd+=("--nopad")
        fi

        local encrypt_result
        if [ "$run_mode" = "profile" ]; then
            encrypt_result=$(time_command nsys profile --output="$BUILD_DIR/${target}_profile" --stats=true --force-overwrite=true "${cmd[@]}")
        else
            encrypt_result=$(time_command "${cmd[@]}")
        fi
        local encrypt_status=${encrypt_result%% *}
        local encrypt_time=${encrypt_result#* }
        if [ "$encrypt_status" -ne 0 ]; then
            echo "  $plaintext_file encrypt FAILED"
            printf "%s: FAIL (encrypt failed)\n" "$test_name" >> "$results_file"
            continue
        fi
        echo "  $plaintext_file encrypt OK (${encrypt_time}ms)"

        cmd=("$BUILD_DIR/$target" "-d" "$encrypted_file" "$key" "$iv" "$decrypted_file")
        if [ "$mode" = "ctr" ]; then
            cmd+=("--nopad")
        fi

        local decrypt_result
        if [ "$run_mode" = "profile" ]; then
            decrypt_result=$(time_command nsys profile --output="$BUILD_DIR/${target}_profile" --stats=true --force-overwrite=true "${cmd[@]}")
        else
            decrypt_result=$(time_command "${cmd[@]}")
        fi
        local decrypt_status=${decrypt_result%% *}
        local decrypt_time=${decrypt_result#* }
        if [ "$decrypt_status" -ne 0 ]; then
            echo "  $plaintext_file decrypt FAILED"
            printf "%s: FAIL (decrypt failed)\n" "$test_name" >> "$results_file"
            continue
        fi
        echo "  $plaintext_file decrypt OK (${decrypt_time}ms)"

        if cmp -s "$decrypted_file" "$plaintext_path"; then
            echo "  $plaintext_file verify PASS"
            printf "%s: PASS (encrypt: %sms, decrypt: %sms)\n" "$test_name" "$encrypt_time" "$decrypt_time" >> "$results_file"
        else
            echo "  $plaintext_file verify FAIL"
            printf "%s: FAIL (verify mismatch)\n" "$test_name" >> "$results_file"
        fi
    done

    printf "\nTest completed at %s\n" "$(date)" >> "$results_file"
}

for cipher in "${SUPPORTED_CIPHERS[@]}"; do
    if ! should_test_cipher "$cipher"; then
        continue
    fi
    for mode in "${SUPPORTED_MODES[@]}"; do
        if ! should_test_mode "$mode"; then
            continue
        fi
        if ! is_gpu_cipher_supported "$cipher"; then
            echo "Skipping GPU $cipher $mode: AES GPU implementation is not available yet."
            output_dir="$RUNS_DIR/gpu/$cipher/$mode"
            mkdir -p "$output_dir"
            results_file="$output_dir/results.txt"
            printf "GPU %s %s Results\n" "$cipher" "$mode" > "$results_file"
            printf "%s\n" "" >> "$results_file"
            printf "Timestamp: %s\n\n" "$(date)" >> "$results_file"
            printf "WARNING: GPU AES implementation is not available yet; test skipped.\n" >> "$results_file"
            continue
        fi
        run_test "$cipher" "$mode"
    done
done

echo ""
echo "All GPU tests completed. Results stored in: $RUNS_DIR/gpu/"