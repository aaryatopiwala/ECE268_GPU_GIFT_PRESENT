#!/usr/bin/env bash
set -euo pipefail

trap 'echo -e "\nExecution aborted by user."; exit 130' SIGINT SIGTERM

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$REPO_DIR/../tests"
RUNS_DIR="$REPO_DIR/../runs"
BUILD_DIR="$REPO_DIR/build"

SUPPORTED_CIPHERS=(present gift aes)
SUPPORTED_MODES=(ctr cbc)

KEYSET="inc"
SELECT_FILE=""

SELECT_CIPHER="all"
SELECT_MODE="all"
OVERRIDE_KEY=""
OVERRIDE_IV=""
PROFILE=false
STATIC_ONLY=false
NO_STATIC=false
CLEAN_BUILD=false

HAS_PERF=false
HAS_CLOC=false
HAS_OBJDUMP=false
HAS_SIZE=false

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
  --profile                        Run perf stat to collect CPU execution metrics.
  --static-only                    Skip encryption tests and only generate source/binary metrics.
  --no-static                      Skip source/binary metrics and only run encryption tests.
  --clean                          Remove the build directory before compiling.
  --help|-h                        Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cipher)      SELECT_CIPHER="${2,,}"; shift 2 ;;
        --mode)        SELECT_MODE="${2,,}";   shift 2 ;;
        --key)         OVERRIDE_KEY="$2";      shift 2 ;;
        --iv)          OVERRIDE_IV="$2";       shift 2 ;;
        --file)        SELECT_FILE="$2";       shift 2 ;;
        --keyset)      KEYSET="${2,,}";        shift 2 ;;
        --profile)     PROFILE=true;           shift   ;;
        --static-only) STATIC_ONLY=true;       shift   ;;
        --no-static)   NO_STATIC=true;         shift   ;;
        --clean)       CLEAN_BUILD=true;       shift   ;;
        --help|-h)     usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [ "$CLEAN_BUILD" = true ] && [ -d "$BUILD_DIR" ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

command -v perf    &>/dev/null && HAS_PERF=true    || true
command -v cloc    &>/dev/null && HAS_CLOC=true    || true
command -v objdump &>/dev/null && HAS_OBJDUMP=true || true
command -v size    &>/dev/null && HAS_SIZE=true    || true

should_test_cipher() { [ "$SELECT_CIPHER" = "all" ] || [ "$1" = "$SELECT_CIPHER" ]; }
should_test_mode()   { [ "$SELECT_MODE"   = "all" ] || [ "$1" = "$SELECT_MODE"   ]; }
num_cpus() { getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }

write_cpu_info() {
    local outfile="$1"
    echo "[cpu_info]" >> "$outfile"
    if command -v lscpu >/dev/null 2>&1; then
        lscpu | grep -iE 'model name|architecture|cpu mhz|L[123] cache' | sed 's/^/  /' >> "$outfile" || true
    elif command -v sysctl >/dev/null 2>&1; then
        sysctl -n machdep.cpu.brand_string 2>/dev/null | sed 's/^/  Model name: /' >> "$outfile" || true
    else
        uname -m | sed 's/^/  Architecture: /' >> "$outfile" || true
    fi
    echo "" >> "$outfile"
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
    esac
}

get_selected_key_ivs() {
    local cipher="$1"
    if [ -n "$OVERRIDE_KEY" ] || [ -n "$OVERRIDE_IV" ]; then
        case "$cipher" in
            present) echo "override:${OVERRIDE_KEY:-00000000000000000000}:${OVERRIDE_IV:-0}" ;;
            gift|aes) echo "override:${OVERRIDE_KEY:-00000000000000000000000000000000}:${OVERRIDE_IV:-00000000000000000000000000000000}" ;;
        esac
        return
    fi
    case "$KEYSET" in
        all) get_key_ivs "$cipher" ;;
        zero|inc|ff) get_key_ivs "$cipher" | awk -F: -v k="$KEYSET" '$1 == k' ;;
        *) echo "Unknown keyset: $KEYSET" >&2; exit 1 ;;
    esac
}

time_command() {
    local start_ns end_ns status=0
    local out_file="$1"
    shift
    
    start_ns=$(date +%s%N)
    "$@" > "$out_file" 2>&1 || status=$?
    [ "$status" -eq 130 ] && kill -INT $$
    end_ns=$(date +%s%N)
    
    printf "%s %s" "$status" "$(( (end_ns - start_ns) / 1000000 ))"
}

throughput_str() {
    local bytes="$1" ms="$2"
    [ "$ms" -le 0 ] && { echo "N/A"; return; }
    local bps=$(( bytes * 1000 / ms ))
    if   [ "$bps" -ge $((1024*1024*1024)) ]; then awk "BEGIN{printf \"%.2f GB/s\", $bps/1073741824}"
    elif [ "$bps" -ge $((1024*1024)) ];      then awk "BEGIN{printf \"%.2f MB/s\", $bps/1048576}"
    else                                          awk "BEGIN{printf \"%.2f KB/s\", $bps/1024}"
    fi
}

build_target() {
    mkdir -p "$BUILD_DIR"
    (
        cd "$BUILD_DIR"
        cmake "$REPO_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
        make -j"$(num_cpus)" >/dev/null 2>&1
    )
}

source_loc_analysis() {
    local cipher="$1"
    local src_dir="$REPO_DIR/$cipher"
    [ -d "$src_dir" ] || src_dir="$REPO_DIR"

    local src_files=()
    while IFS= read -r f; do
        src_files+=("$f")
    done < <(find "$src_dir" -maxdepth 3 -name "*.cpp" -o -name "*.hpp" -o -name "*.h" 2>/dev/null | sort)

    echo "[source_loc cipher=$cipher]"

    if [ ${#src_files[@]} -eq 0 ]; then
        echo "  source_files=none_found"
    else
        for f in "${src_files[@]}"; do
            local rel="${f#$REPO_DIR/}"
            local total blank comment code
            total=$(awk 'END{print NR}' "$f")
            blank=$(awk '/^[[:space:]]*$/{c++} END{print c+0}' "$f")
            comment=$(awk '/^[[:space:]]*\/\// {c++; next}; /^[[:space:]]*\/\*/ {in_b=1}; in_b && /\*\// {in_b=0; c++; next}; in_b {c++}; END{print c+0}' "$f")
            code=$(( total - blank - comment ))

            printf "  file=%-25s total=%-5s blank=%-5s comment=%-5s code=%s\n" "$rel" "$total" "$blank" "$comment" "$code"
        done

        if [ "$HAS_CLOC" = true ]; then
            local cloc_code
            cloc_code=$(cloc --quiet --csv "${src_files[@]}" 2>/dev/null | awk -F, '/C\+\+|C\/C\+\+Header|C/{sum+=$NF} END{print sum+0}')
            printf "  cloc_total_code_lines=%s\n" "${cloc_code:-N/A}"
        fi
    fi
}

binary_analysis() {
    local cipher="$1" binary="$2"
    echo "[binary_analysis cipher=$cipher binary=$(basename "$binary")]"

    if [ ! -f "$binary" ]; then
        echo "  binary_missing"
        return
    fi

    local bin_bytes
    bin_bytes=$(wc -c < "$binary" | tr -d ' ')
    printf "  total_size_bytes=%s\n" "$bin_bytes"

    if [ "$HAS_SIZE" = true ]; then
        size -A "$binary" 2>/dev/null | awk '
            /\.text/   { printf "  text_segment_bytes=%s\n", $2 }
            /\.data/   { printf "  data_segment_bytes=%s\n", $2 }
            /\.bss/    { printf "  bss_segment_bytes=%s\n", $2 }
            /\.rodata/ { printf "  rodata_segment_bytes=%s\n", $2 }
        '
    fi

    if [ "$HAS_OBJDUMP" = true ]; then
        local inst_count
        inst_count=$(objdump -d "$binary" 2>/dev/null | grep -E '^[[:space:]]*[0-9a-f]+:' | wc -l | tr -d ' ')
        printf "  total_assembly_instructions=%s\n" "$inst_count"
    fi
}

perf_run() {
    local binary="$1" label="$2" out_dir="$3"; shift 3
    local out="${out_dir}/perf_${label}.txt"
    [ "$HAS_PERF" = false ] && { echo ""; return; }

    local status=0
    perf stat -e task-clock,cycles,instructions,cache-references,cache-misses,branches,branch-misses \
        -o "$out" -- "$binary" "$@" >/dev/null 2>&1 || status=$?

    [ "$status" -eq 130 ] && { kill -INT $$; return; }
    echo "$out"
}

parse_perf() {
    local txt="$1"
    [ ! -f "$txt" ] && { echo "    perf_log=missing"; return; }
    grep -E 'task-clock|cycles|instructions|cache-references|cache-misses|branches|branch-misses' "$txt" | awk '
        {
            val = $1; sub(/,/, "", val)
            desc = $2; for(i=3; i<=NF; i++) { if($i ~ /#/) break; desc = desc " " $i }
            printf "    [PERF] %-20s : %s\n", desc, val
        }
    '
}

static_analysis_cipher() {
    local cipher="$1"
    local out_dir="$RUNS_DIR/cpu/$cipher"
    mkdir -p "$out_dir"
    local out_file="$out_dir/static_analysis.txt"

    {
        printf "cipher=%s\n"      "$cipher"
        printf "timestamp=%s\n\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        source_loc_analysis "$cipher"
        echo ""

        local probe_mode=""
        for m in "${SUPPORTED_MODES[@]}"; do
            should_test_mode "$m" && { probe_mode="$m"; break; }
        done

        if [ -n "$probe_mode" ]; then
            local probe_target="${cipher}_${probe_mode}"
            build_target 2>/dev/null || true

            if [ -f "$BUILD_DIR/$probe_target" ]; then
                binary_analysis "$cipher" "$BUILD_DIR/$probe_target"
                echo ""
            fi
        fi
    } > "$out_file"

    echo "  static_analysis -> $out_file"
}

run_test() {
    local cipher="$1" mode="$2"
    local target="${cipher}_${mode}"
    local output_dir="$RUNS_DIR/cpu/$cipher/$mode"
    mkdir -p "$output_dir"
    local results_file="$output_dir/results.txt"

    if ! build_target; then
        echo "build_failed cipher=$cipher mode=$mode" | tee "$results_file"
        return 1
    fi

    if [ ! -f "$BUILD_DIR/$target" ]; then
        echo "binary_missing cipher=$cipher mode=$mode path=$BUILD_DIR/$target" | tee -a "$results_file"
        return 1
    fi

    {
        printf "cipher=%s mode=%s\n"   "$cipher" "$mode"
        printf "binary=%s\n"           "$BUILD_DIR/$target"
        printf "timestamp=%s\n"        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf "profile=%s\n\n"        "$PROFILE"
    } > "$results_file"
    
    write_cpu_info "$results_file"

    echo "[results cipher=$cipher mode=$mode]" >> "$results_file"
    printf "%-42s  %-6s  %-12s  %-12s  %-12s  %-12s  %s\n" \
    "file" "status" "enc_time" "enc_tput" "dec_time" "dec_tput" "verify" \
    >> "$results_file"

    for plaintext_path in $(get_plaintext_files); do
        local plaintext_file=$(basename "$plaintext_path")
        local file_bytes=$(wc -c < "$plaintext_path" | tr -d ' ')
        
        while IFS= read -r key_iv_entry; do
            [ -z "$key_iv_entry" ] && continue
            local key_name key iv
            IFS=':' read -r key_name key iv <<< "$key_iv_entry"
        
            local test_name="${plaintext_file}_${key_name}"
            local display_name="${plaintext_file}[$key_name]"
            local encrypted_file="$output_dir/${test_name}.enc"
            local decrypted_file="$output_dir/${test_name}.dec"
    
            local enc_cmd=("$BUILD_DIR/$target" "-e" "$plaintext_path" "$key" "$iv" "$encrypted_file")
            local dec_cmd=("$BUILD_DIR/$target" "-d" "$encrypted_file"  "$key" "$iv" "$decrypted_file")
            
            if [ "$mode" = "ctr" ]; then
                enc_cmd+=("--nopad")
                dec_cmd+=("--nopad")
            fi
    
            local enc_stdout_file="$output_dir/${test_name}.enc.out"
            local enc_result enc_status enc_ms
            enc_result=$(time_command "$enc_stdout_file" "${enc_cmd[@]}")
            enc_status=${enc_result%% *}; enc_ms=${enc_result#* }
            
            if [ "$enc_status" -ne 0 ]; then
                {
                    printf "%-42s  FAIL    enc_failed (exit=%s)\n" "$plaintext_file" "$enc_status"
                } | tee -a "$results_file"
                rm -f "$enc_stdout_file"
                continue
            fi
            local enc_tput; enc_tput=$(throughput_str "$file_bytes" "$enc_ms")
    
            local dec_stdout_file="$output_dir/${test_name}.dec.out"
            local dec_result dec_status dec_ms
            dec_result=$(time_command "$dec_stdout_file" "${dec_cmd[@]}")
            dec_status=${dec_result%% *}; dec_ms=${dec_result#* }
            
            if [ "$dec_status" -ne 0 ]; then
                {
                    printf "%-42s  FAIL    dec_failed\n" "$plaintext_file"
                } | tee -a "$results_file"
                rm -f "$encrypted_file" "$enc_stdout_file" "$dec_stdout_file"
                continue
            fi
            local dec_tput; dec_tput=$(throughput_str "$file_bytes" "$dec_ms")
    
            local verify="PASS"
            cmp -s "$decrypted_file" "$plaintext_path" || verify="FAIL"
    
            printf "%-42s  PASS    %-12s  %-12s  %-12s  %-12s  %s\n" \
            "$display_name" "${enc_ms} ms" "$enc_tput" "${dec_ms} ms" "$dec_tput" "$verify" \
            | tee -a "$results_file"
    
            if [ "$PROFILE" = true ]; then
                local perf_log
                perf_log=$(perf_run "${enc_cmd[0]}" "${test_name}_enc" "$output_dir" "${enc_cmd[@]:1}")
                if [ -n "$perf_log" ]; then
                    {
                        printf "  [perf file=%s op=encrypt]\n" "$plaintext_file"
                        parse_perf "$perf_log"
                    } >> "$results_file"
                    rm -f "$perf_log"
                fi
            fi

            rm -f "$encrypted_file" "$decrypted_file" "$enc_stdout_file" "$dec_stdout_file"
            
        done < <(get_selected_key_ivs "$cipher")
    done

    echo "" >> "$results_file"
    printf "completed=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$results_file"
    echo "  -> $results_file"
}

declare -A STATIC_DONE

for cipher in "${SUPPORTED_CIPHERS[@]}"; do
    should_test_cipher "$cipher" || continue

    if [ "$NO_STATIC" = false ] && [ -z "${STATIC_DONE[$cipher]+x}" ]; then
        echo "static_analysis cipher=$cipher"
        static_analysis_cipher "$cipher"
        STATIC_DONE[$cipher]=1
    fi

    if [ "$STATIC_ONLY" = true ]; then
        continue
    fi

    for mode in "${SUPPORTED_MODES[@]}"; do
        should_test_mode "$mode" || continue
        echo "running cipher=$cipher mode=$mode"
        run_test "$cipher" "$mode"
    done
done