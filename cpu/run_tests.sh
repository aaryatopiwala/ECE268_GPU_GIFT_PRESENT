# #!/usr/bin/env bash
# set -euo pipefail

# REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# TESTS_DIR="$REPO_DIR/../tests"
# RUNS_DIR="$REPO_DIR/../runs"

# SUPPORTED_CIPHERS=(present gift aes)
# SUPPORTED_MODES=(ctr cbc)

# declare -A DEFAULT_KEY_IV
# DEFAULT_KEY_IV=(
#     ["beemovie.txt"]="00000000000000000000:0"
#     ["moderntimes.mp4"]="00000000000000000000:0"
# )

# SELECT_CIPHER="all"
# SELECT_MODE="all"
# OVERRIDE_KEY=""
# OVERRIDE_IV=""
# PROFILE=false

# usage() {
#     cat <<EOF
# Usage: $0 [options]

# Options:
#   --cipher <present|gift|aes|all>   Select cipher to test (default: all)
#   --mode <ctr|cbc|all>              Select mode to test (default: all)
#   --key <hex>                       Override default key for all test files
#   --iv <hex>                        Override default IV for all test files
#   --profile                         Enable timing output only; CPU does not use nsys
#   --help                            Show this help message
# EOF
# }

# while [[ $# -gt 0 ]]; do
#     case "$1" in
#         --cipher)
#             SELECT_CIPHER="${2,,}"
#             shift 2
#             ;;
#         --mode)
#             SELECT_MODE="${2,,}"
#             shift 2
#             ;;
#         --key)
#             OVERRIDE_KEY="$2"
#             shift 2
#             ;;
#         --iv)
#             OVERRIDE_IV="$2"
#             shift 2
#             ;;
#         --profile)
#             PROFILE=true
#             shift
#             ;;
#         --help|-h)
#             usage
#             exit 0
#             ;;
#         *)
#             echo "Unknown option: $1" >&2
#             usage
#             exit 1
#             ;;
#     esac
# done

# if [ "$PROFILE" = true ]; then
#     echo "NOTE: CPU profiling is not supported in this script; only timing summaries are written."
# fi

# get_plaintext_files() {
#     find "$TESTS_DIR" -maxdepth 1 -type f \( -name "*.bin" -o -name "*.txt" -o -name "*.mp4" \) ! -name "*de.*" | sort
# }

# should_test_cipher() {
#     local cipher="$1"
#     if [ "$SELECT_CIPHER" = "all" ]; then
#         return 0
#     fi
#     [ "$cipher" = "$SELECT_CIPHER" ]
# }

# should_test_mode() {
#     local mode="$1"
#     if [ "$SELECT_MODE" = "all" ]; then
#         return 0
#     fi
#     [ "$mode" = "$SELECT_MODE" ]
# }

# time_command() {
#     local start_ns end_ns status
#     start_ns=$(date +%s%N)
    
#     # Temporarily disable error stopping to catch the exact exit code, then re-enable
#     set +e 
#     "$@" >/dev/null 2>&1
#     status=$?
#     set -e
    
#     end_ns=$(date +%s%N)
#     printf "%s %s" "$status" "$(( (end_ns - start_ns) / 1000000 ))"
# }

# run_test() {
#     local cipher="$1"
#     local mode="$2"
#     local binary_dir="$REPO_DIR/$cipher"
#     local binary_name="${cipher}_${mode}"
#     local binary_path="$binary_dir/$binary_name"

#     echo ""
#     echo "CPU $cipher $mode tests"

#     cd "$binary_dir"
#     if ! make "$binary_name" >/dev/null 2>&1; then
#         echo "ERROR: Failed to build $binary_name" >&2
#         return 1
#     fi

#     # Ensure binary is executable
#     chmod +x "$binary_path"

#     local output_dir="$RUNS_DIR/cpu/$cipher/$mode"
#     mkdir -p "$output_dir"
#     local results_file="$output_dir/results.txt"

#     printf "CPU %s %s Results\n" "$cipher" "$mode" > "$results_file"
#     printf "%s\n" "" >> "$results_file"
#     printf "Timestamp: %s\n\n" "$(date)" >> "$results_file"

#     for plaintext_path in $(get_plaintext_files); do
#         local plaintext_file
#         plaintext_file=$(basename "$plaintext_path")
#         local key_iv
#         if [ -n "$OVERRIDE_KEY" ] || [ -n "$OVERRIDE_IV" ]; then
#             key_iv="${OVERRIDE_KEY:-00000000000000000000}:${OVERRIDE_IV:-0}"
#         else
#             key_iv="${DEFAULT_KEY_IV[$plaintext_file]:-00000000000000000000:0}"
#         fi

#         local key iv
#         IFS=':' read -r key iv <<< "$key_iv"
#         local test_name="${plaintext_file}_key_${key:0:4}_${key: -4}"
#         local encrypted_file="$output_dir/${test_name}.enc"
#         local decrypted_file="$output_dir/${test_name}.dec"

#         # Dynamically build the execution array to prevent empty argument parsing bugs
#         local cmd=("$binary_path" "-e" "$plaintext_path" "$key" "$iv" "$encrypted_file")
#         if [ "$mode" = "ctr" ]; then
#             cmd+=("--nopad")
#         fi

#         local encrypt_result
#         encrypt_result=$(time_command "${cmd[@]}")
#         local encrypt_status=${encrypt_result%% *}
#         local encrypt_time=${encrypt_result#* }
        
#         if [ "$encrypt_status" -ne 0 ]; then
#             echo "  $plaintext_file encrypt FAILED"
#             printf "%s: FAIL (encrypt failed)\n" "$test_name" >> "$results_file"
#             continue
#         fi
#         echo "  $plaintext_file encrypt OK (${encrypt_time}ms)"

#         # Re-build the array for decryption
#         local cmd_dec=("$binary_path" "-d" "$encrypted_file" "$key" "$iv" "$decrypted_file")
#         if [ "$mode" = "ctr" ]; then
#             cmd_dec+=("--nopad")
#         fi

#         local decrypt_result
#         decrypt_result=$(time_command "${cmd_dec[@]}")
#         local decrypt_status=${decrypt_result%% *}
#         local decrypt_time=${decrypt_result#* }
        
#         if [ "$decrypt_status" -ne 0 ]; then
#             echo "  $plaintext_file decrypt FAILED"
#             printf "%s: FAIL (decrypt failed)\n" "$test_name" >> "$results_file"
#             continue
#         fi
#         echo "  $plaintext_file decrypt OK (${decrypt_time}ms)"

#         if cmp -s "$decrypted_file" "$plaintext_path"; then
#             echo "  $plaintext_file verify PASS"
#             printf "%s: PASS (encrypt: %sms, decrypt: %sms)\n" "$test_name" "$encrypt_time" "$decrypt_time" >> "$results_file"
#         else
#             echo "  $plaintext_file verify FAIL"
#             printf "%s: FAIL (verify mismatch)\n" "$test_name" >> "$results_file"
#         fi
#     done

#     printf "\nTest completed at %s\n" "$(date)" >> "$results_file"
# }

# for cipher in "${SUPPORTED_CIPHERS[@]}"; do
#     if ! should_test_cipher "$cipher"; then
#         continue
#     fi
#     for mode in "${SUPPORTED_MODES[@]}"; do
#         if ! should_test_mode "$mode"; then
#             continue
#         fi
#         run_test "$cipher" "$mode"
#     done
# done

# echo ""
# echo "All CPU tests completed. Results stored in: $RUNS_DIR/cpu/"


#!/usr/bin/env bash
set -euo pipefail

trap 'echo -e "\nExecution aborted by user."; exit 130' SIGINT SIGTERM

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$REPO_DIR/../tests"
RUNS_DIR="$REPO_DIR/../runs"

SUPPORTED_CIPHERS=(present gift aes)
SUPPORTED_MODES=(ctr cbc)

SELECT_CIPHER="all"
SELECT_MODE="all"
SELECT_FILE=""
KEYSET="inc"
OVERRIDE_KEY=""
OVERRIDE_IV=""
PROFILE=false
STATIC_ONLY=false
NO_STATIC=false
CLEAN_BUILD=false

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --file <filename>                Test only one plaintext file.
  --keyset <zero|inc|ff|all>       Select built-in key/IV vector set (default: inc).
  --cipher <present|gift|aes|all>  Specify the target cipher algorithm.
  --mode <ctr|cbc|all>             Specify the block cipher mode of operation.
  --key <hex>                      Override the default encryption key.
  --iv <hex>                       Override the default initialization vector.
  --profile                        Enable timing output only; CPU does not use nsys.
  --static-only                    Accepted for compatibility; CPU static analysis is not implemented.
  --no-static                      Accepted for compatibility.
  --clean                          Run make clean before building each CPU target.
  --help|-h                        Show this help message.
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
        --file)
            SELECT_FILE="$2"
            shift 2
            ;;
        --keyset)
            KEYSET="${2,,}"
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
        --static-only)
            STATIC_ONLY=true
            shift
            ;;
        --no-static)
            NO_STATIC=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
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

if [ "$STATIC_ONLY" = true ]; then
    echo "NOTE: CPU static analysis is not implemented in this script."
    echo "All CPU tests skipped because --static-only was requested."
    exit 0
fi

get_key_ivs() {
    local cipher="$1"

    case "$cipher" in
        present)
            echo "zero:00000000000000000000:0"
            echo "inc:00112233445566778899:0102030405060708"
            echo "ff:ffffffffffffffffffff:ffffffffffffffff"
            ;;
        gift|aes)
            echo "zero:00000000000000000000000000000000:00000000000000000000000000000000"
            echo "inc:00112233445566778899aabbccddeeff:0102030405060708090a0b0c0d0e0f10"
            echo "ff:ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff"
            ;;
        *)
            echo "Unknown cipher: $cipher" >&2
            exit 1
            ;;
    esac
}

get_selected_key_ivs() {
    local cipher="$1"

    if [ -n "$OVERRIDE_KEY" ] || [ -n "$OVERRIDE_IV" ]; then
        case "$cipher" in
            present)
                echo "override:${OVERRIDE_KEY:-00000000000000000000}:${OVERRIDE_IV:-0}"
                ;;
            gift|aes)
                echo "override:${OVERRIDE_KEY:-00000000000000000000000000000000}:${OVERRIDE_IV:-00000000000000000000000000000000}"
                ;;
            *)
                echo "Unknown cipher: $cipher" >&2
                exit 1
                ;;
        esac
        return
    fi

    case "$KEYSET" in
        all)
            get_key_ivs "$cipher"
            ;;
        zero|inc|ff)
            get_key_ivs "$cipher" | awk -F: -v k="$KEYSET" '$1 == k'
            ;;
        *)
            echo "Unknown keyset: $KEYSET" >&2
            echo "Expected one of: zero, inc, ff, all" >&2
            exit 1
            ;;
    esac
}

get_plaintext_files() {
    if [ -n "$SELECT_FILE" ]; then
        find "$TESTS_DIR" -maxdepth 1 -type f -name "$SELECT_FILE" | sort
    else
        find "$TESTS_DIR" -maxdepth 1 -type f \
            \( -name "*.bin" -o -name "*.txt" -o -name "*.mp4" -o -name "*.dat" -o -name "*.raw" \) \
            ! -name "*de.*" | sort
    fi
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

    set +e
    start_ns=$(date +%s%N)
    "$@" >/dev/null 2>&1
    status=$?
    end_ns=$(date +%s%N)
    set -e

    [ "$status" -eq 130 ] && kill -INT $$

    printf "%s %s" "$status" "$(( (end_ns - start_ns) / 1000000 ))"
}

throughput_str() {
    local bytes="$1"
    local ms="$2"

    [ "$ms" -le 0 ] && { echo "N/A"; return; }

    local bps=$(( bytes * 1000 / ms ))

    if [ "$bps" -ge $((1024*1024*1024)) ]; then
        awk "BEGIN{printf \"%.2f GB/s\", $bps/1073741824}"
    elif [ "$bps" -ge $((1024*1024)) ]; then
        awk "BEGIN{printf \"%.2f MB/s\", $bps/1048576}"
    else
        awk "BEGIN{printf \"%.2f KB/s\", $bps/1024}"
    fi
}

size_str() {
    local bytes="$1"

    if [ "$bytes" -ge $((1024*1024*1024)) ]; then
        awk "BEGIN{printf \"%.2f GB\", $bytes/1073741824}"
    elif [ "$bytes" -ge $((1024*1024)) ]; then
        awk "BEGIN{printf \"%.2f MB\", $bytes/1048576}"
    else
        awk "BEGIN{printf \"%.2f KB\", $bytes/1024}"
    fi
}

build_target() {
    local binary_dir="$1"
    local binary_name="$2"

    cd "$binary_dir"

    if [ "$CLEAN_BUILD" = true ]; then
        make clean >/dev/null 2>&1 || true
    fi

    make "$binary_name" >/dev/null 2>&1
}

run_test() {
    local cipher="$1"
    local mode="$2"
    local binary_dir="$REPO_DIR/$cipher"
    local binary_name="${cipher}_${mode}"
    local binary_path="$binary_dir/$binary_name"

    echo ""
    echo "CPU $cipher $mode tests"

    if ! build_target "$binary_dir" "$binary_name"; then
        echo "ERROR: Failed to build $binary_name" >&2
        return 1
    fi

    chmod +x "$binary_path"

    local output_dir="$RUNS_DIR/cpu/$cipher/$mode"
    mkdir -p "$output_dir"

    local results_file="$output_dir/results.txt"

    {
        printf "CPU %s %s Results\n\n" "$cipher" "$mode"
        printf "binary=%s\n" "$binary_path"
        printf "timestamp=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf "profile=%s\n" "$PROFILE"
        printf "keyset=%s\n\n" "$KEYSET"

        printf "%-42s  %-10s  %-6s  %-12s  %-12s  %-12s  %-12s  %s\n" \
            "file" "size" "status" "enc_time" "enc_tput" "dec_time" "dec_tput" "verify"
    } > "$results_file"

    local plaintext_paths
    plaintext_paths=$(get_plaintext_files)

    if [ -z "$plaintext_paths" ]; then
        echo "  No plaintext files found."
        printf "No plaintext files found.\n" >> "$results_file"
        return 0
    fi

    while IFS= read -r plaintext_path; do
        [ -z "$plaintext_path" ] && continue

        local plaintext_file
        plaintext_file=$(basename "$plaintext_path")

        local file_bytes
        file_bytes=$(wc -c < "$plaintext_path" | tr -d ' ')

        local file_size
        file_size=$(size_str "$file_bytes")

        while IFS= read -r key_iv_entry; do
            [ -z "$key_iv_entry" ] && continue

            local key_name key iv
            IFS=':' read -r key_name key iv <<< "$key_iv_entry"

            local display_name="${plaintext_file}[$key_name]"
            local test_name="${plaintext_file}_${key_name}"

            local encrypted_file="$output_dir/${test_name}.enc"
            local decrypted_file="$output_dir/${test_name}.dec"

            local enc_cmd=("$binary_path" "-e" "$plaintext_path" "$key" "$iv" "$encrypted_file")
            if [ "$mode" = "ctr" ]; then
                enc_cmd+=("--nopad")
            fi

            local encrypt_result encrypt_status encrypt_ms
            encrypt_result=$(time_command "${enc_cmd[@]}")
            encrypt_status=${encrypt_result%% *}
            encrypt_ms=${encrypt_result#* }

            if [ "$encrypt_status" -ne 0 ]; then
                echo "  $display_name encrypt FAILED"
                printf "%-42s  %-10s  FAIL    enc_failed exit=%s\n" \
                    "$display_name" "$file_size" "$encrypt_status" >> "$results_file"
                rm -f "$encrypted_file" "$decrypted_file"
                continue
            fi

            local enc_tput
            enc_tput=$(throughput_str "$file_bytes" "$encrypt_ms")

            local dec_cmd=("$binary_path" "-d" "$encrypted_file" "$key" "$iv" "$decrypted_file")
            if [ "$mode" = "ctr" ]; then
                dec_cmd+=("--nopad")
            fi

            local decrypt_result decrypt_status decrypt_ms
            decrypt_result=$(time_command "${dec_cmd[@]}")
            decrypt_status=${decrypt_result%% *}
            decrypt_ms=${decrypt_result#* }

            if [ "$decrypt_status" -ne 0 ]; then
                echo "  $display_name decrypt FAILED"
                printf "%-42s  %-10s  FAIL    dec_failed exit=%s\n" \
                    "$display_name" "$file_size" "$decrypt_status" >> "$results_file"
                rm -f "$encrypted_file" "$decrypted_file"
                continue
            fi

            local dec_tput
            dec_tput=$(throughput_str "$file_bytes" "$decrypt_ms")

            local verify="PASS"
            cmp -s "$decrypted_file" "$plaintext_path" || verify="FAIL"

            printf "%-42s  %-10s  PASS    %-12s  %-12s  %-12s  %-12s  %s\n" \
                "$display_name" "$file_size" "${encrypt_ms} ms" "$enc_tput" "${decrypt_ms} ms" "$dec_tput" "$verify" \
                | tee -a "$results_file"

            rm -f "$encrypted_file" "$decrypted_file"
        done < <(get_selected_key_ivs "$cipher")
    done <<< "$plaintext_paths"

    printf "\nTest completed at %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$results_file"
    echo "  -> $results_file"
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