#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$REPO_DIR/../tests"
RUNS_DIR="$REPO_DIR/../runs"

SUPPORTED_CIPHERS=(present gift aes)
SUPPORTED_MODES=(ctr cbc)
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
  --profile                         Enable timing output only; CPU does not use nsys
  --help                            Show this help message
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

if [ "$PROFILE" = true ]; then
    echo "NOTE: CPU profiling is not supported in this script; only timing summaries are written."
fi

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

time_command() {
    local start_ns end_ns status
    start_ns=$(date +%s%N)
    "$@"
    status=$?
    end_ns=$(date +%s%N)
    printf "%s %s" "$status" "$(( (end_ns - start_ns) / 1000000 ))"
    return $status
}

run_test() {
    local cipher="$1"
    local mode="$2"
    local binary_dir="$REPO_DIR/$cipher"
    local binary_name="${cipher}_${mode}"
    local binary_path="$binary_dir/$binary_name"

    echo ""
    echo "CPU $cipher $mode tests"

    cd "$binary_dir"
    if ! make "$binary_name" >/dev/null 2>&1; then
        echo "ERROR: Failed to build $binary_name" >&2
        return 1
    fi

    local output_dir="$RUNS_DIR/cpu/$cipher/$mode"
    mkdir -p "$output_dir"
    local results_file="$output_dir/results.txt"

    printf "CPU %s %s Results\n" "$cipher" "$mode" > "$results_file"
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

        local encrypt_result
        encrypt_result=$(time_command "$binary_path" -e "$TESTS_DIR/$plaintext_file" "$key" "$iv" "$encrypted_file" $( [ "$mode" = "ctr" ] && printf -- '--nopad' ) >/dev/null 2>&1 || true)
        local encrypt_status=${encrypt_result%% *}
        local encrypt_time=${encrypt_result#* }
        if [ "$encrypt_status" -ne 0 ]; then
            echo "  $plaintext_file encrypt FAILED"
            printf "%s: FAIL (encrypt failed)\n" "$test_name" >> "$results_file"
            continue
        fi
        echo "  $plaintext_file encrypt OK (${encrypt_time}ms)"

        local decrypt_result
        decrypt_result=$(time_command "$binary_path" -d "$encrypted_file" "$key" "$iv" "$decrypted_file" $( [ "$mode" = "ctr" ] && printf -- '--nopad' ) >/dev/null 2>&1 || true)
        local decrypt_status=${decrypt_result%% *}
        local decrypt_time=${decrypt_result#* }
        if [ "$decrypt_status" -ne 0 ]; then
            echo "  $plaintext_file decrypt FAILED"
            printf "%s: FAIL (decrypt failed)\n" "$test_name" >> "$results_file"
            continue
        fi
        echo "  $plaintext_file decrypt OK (${decrypt_time}ms)"

        if cmp -s "$decrypted_file" "$TESTS_DIR/$plaintext_file"; then
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
        run_test "$cipher" "$mode"
    done
done

echo ""
echo "All CPU tests completed. Results stored in: $RUNS_DIR/cpu/"
