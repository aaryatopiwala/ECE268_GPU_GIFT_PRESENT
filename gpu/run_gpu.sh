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

HAS_NSYS=false
HAS_CUOBJDUMP=false
HAS_CLOC=false

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
  --profile                        Run Nsight Systems (nsys) to collect kernel execution times.
  --static-only                    Skip encryption tests and only generate source/PTX/CUBIN metrics.
  --no-static                      Skip source/PTX/CUBIN metrics and only run encryption tests.
  --clean                          Remove the build directory before compiling.
  --help|-h                        Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cipher)      SELECT_CIPHER="${2,,}"; shift 2 ;;
        --mode)        SELECT_MODE="${2,,}";   shift 2 ;;
        --key)         OVERRIDE_KEY="$2";     shift 2 ;;
        --iv)          OVERRIDE_IV="$2";      shift 2 ;;
        --file)        SELECT_FILE="$2"; shift 2 ;;
        --keyset)      KEYSET="${2,,}";  shift 2 ;;
        --profile)     PROFILE=true;          shift   ;;
        --static-only) STATIC_ONLY=true;      shift   ;;
        --no-static)   NO_STATIC=true;        shift   ;;
        --clean)       CLEAN_BUILD=true;      shift   ;;
        --help|-h)     usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [ "$CLEAN_BUILD" = true ] && [ -d "$BUILD_DIR" ]; then
    echo "Cleaning build directory..."
    find "$BUILD_DIR" -mindepth 1 -delete 2>/dev/null || true
fi

if command -v nvidia-smi &> /dev/null; then
    nvidia-smi >/dev/null || { echo "CRITICAL ERROR: nvidia-smi failed. GPU driver is missing or broken on this node."; exit 1; }
else
    echo "CRITICAL ERROR: nvidia-smi not found. This node does not have NVIDIA tools installed."
    exit 1
fi

command -v nsys      &>/dev/null && HAS_NSYS=true      || true
command -v cuobjdump &>/dev/null && HAS_CUOBJDUMP=true || true
command -v cloc      &>/dev/null && HAS_CLOC=true      || true

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
    elif [ "$bps" -ge $((1024*1024)) ]; then awk "BEGIN{printf \"%.2f MB/s\", $bps/1048576}"
    else awk "BEGIN{printf \"%.2f KB/s\", $bps/1024}"
    fi
}

strip_gpu_info() {
    awk '
        /\[gpu_info\]/ { skip = 1; next }
        skip && /----/ { next }
        skip && /Dev[[:space:]]+Name/ { next }
        skip && /^[[:space:]]*[0-9]+[[:space:]]+/ { next }
        skip && /^[[:space:]]*$/ { skip = 0; next }
        skip { skip = 0 }
        { print }
    '
}

build_target() {
    local target="$1" ptxas_log="$2"
    mkdir -p "$BUILD_DIR"
    (
        cd "$BUILD_DIR"
        cmake "$REPO_DIR" -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_CUDA_FLAGS="-Xptxas -v --generate-line-info" \
            >/dev/null 2>&1
        rm -f "$target"
        make -j"$(num_cpus)" "$target" 2>"$ptxas_log.raw" >/dev/null || { cat "$ptxas_log.raw" >&2; exit 1; }
        grep -E "ptxas info:|Used [0-9]+ registers|lmem|smem|cmem" "$ptxas_log.raw" > "$ptxas_log" || true
        rm -f "$ptxas_log.raw"
    )
}

count_code_lines_awk() {
    awk '
        /^[[:space:]]*$/    { next }
        /^[[:space:]]*\/\// { next }
        /^[[:space:]]*\/\*/ { in_block=1 }
        in_block && /\*\//  { in_block=0; next }
        in_block            { next }
        { code++ }
        END { print code+0 }
    ' "$@"
}

source_loc_analysis() {
    local cipher="$1"
    local src_dir="$REPO_DIR/$cipher"
    [ -d "$src_dir" ] || src_dir="$REPO_DIR/src/$cipher"
    [ -d "$src_dir" ] || src_dir="$REPO_DIR"

    local kernel_files=()
    while IFS= read -r f; do
        kernel_files+=("$f")
    done < <(find "$src_dir" -maxdepth 3 \
        \( -name "${cipher}.cuh" -o -name "${cipher}.cu" \) \
        ! -name "${cipher}_*" 2>/dev/null | sort)

    local harness_files=()
    while IFS= read -r f; do
        harness_files+=("$f")
    done < <(find "$src_dir" -maxdepth 3 \
        -name "${cipher}_*.cu" 2>/dev/null | sort)

    echo "[source_loc cipher=$cipher]"

    if [ ${#kernel_files[@]} -eq 0 ]; then
        echo "  kernel_files=none_found"
    else
        for f in "${kernel_files[@]}"; do
            local rel="${f#$REPO_DIR/}"
            local total blank comment code
            total=$(  awk 'END{print NR}' "$f")
            blank=$(  awk '/^[[:space:]]*$/{c++} END{print c+0}' "$f")
            comment=$(awk '
                /^[[:space:]]*\/\// {c++; next}
                /^[[:space:]]*\/\*/ {in_b=1}
                in_b && /\*\// {in_b=0; c++; next}
                in_b {c++}
                END{print c+0}' "$f")
            code=$(( total - blank - comment ))

            printf "  kernel_file=%s\n"       "$rel"
            printf "    loc_total=%s\n"       "$total"
            printf "    loc_blank=%s\n"       "$blank"
            printf "    loc_comment=%s\n"     "$comment"
            printf "    loc_code=%s\n"        "$code"

            local n_global n_device
            n_global=$(grep -c "^__global__" "$f" 2>/dev/null || true); n_global=${n_global:-0}
            n_device=$( grep -c "^__device__" "$f" 2>/dev/null || true); n_device=${n_device:-0}
            printf "    kernel_functions=%s\n" "$n_global"
            printf "    device_functions=%s\n" "$n_device"
        done

        local total_kernel_code
        total_kernel_code=$(count_code_lines_awk "${kernel_files[@]}")
        printf "  kernel_total_loc_code=%s\n" "$total_kernel_code"
    fi

    if [ ${#harness_files[@]} -gt 0 ]; then
        local total_harness_code
        total_harness_code=$(count_code_lines_awk "${harness_files[@]}")
        printf "  harness_total_loc_code=%s\n" "$total_harness_code"
        for f in "${harness_files[@]}"; do
            printf "  harness_file=%s\n" "${f#$REPO_DIR/}"
        done
    fi

    if [ "$HAS_CLOC" = true ] && [ ${#kernel_files[@]} -gt 0 ]; then
        local cloc_code
        cloc_code=$(cloc --quiet --csv "${kernel_files[@]}" 2>/dev/null \
            | awk -F, '/CUDA|C\/C\+\+Header|C\+\+/{sum+=$NF} END{print sum+0}')
        printf "  cloc_code_lines=%s\n" "${cloc_code:-N/A}"
    fi
}

ptx_analysis() {
    local cipher="$1" target="$2"
    local ptx_file="$BUILD_DIR/${target}.ptx"

    echo "[ptx cipher=$cipher target=$target]"

    local src_file
    src_file=$(find "$REPO_DIR" -maxdepth 4 -name "${target}.cu" 2>/dev/null | head -1)

    if [ -z "$src_file" ]; then
        echo "  ptx_source=not_found"
        return
    fi

    local inc_dirs=("-I$REPO_DIR")
    while IFS= read -r d; do
        inc_dirs+=("-I$d")
    done < <(find "$REPO_DIR" -maxdepth 3 -type d \( -name "utils" -o -name "include" \) 2>/dev/null)

    nvcc --ptx "${inc_dirs[@]}" \
        -O2 \
        --generate-line-info \
        -o "$ptx_file" \
        "$src_file" \
        >/dev/null 2>&1 || { echo "  ptx_compile=failed"; return; }

    [ -f "$ptx_file" ] || { echo "  ptx_file=missing"; return; }

    local ptx_bytes ptx_lines ptx_instr_lines
    ptx_bytes=$(     wc -c < "$ptx_file" | tr -d ' ')
    ptx_lines=$(     awk 'END{print NR}' "$ptx_file")
    ptx_instr_lines=$(awk '
        /^[[:space:]]*$/    { next }
        /^[[:space:]]*\/\// { next }
        /^[[:space:]]*\./   { next }
        /^[[:space:]]*\/\*/ { in_b=1 }
        in_b && /\*\//      { in_b=0; next }
        in_b                { next }
        /^[[:space:]]*[a-zA-Z_][^:]*:$/ { next }
        { count++ }
        END { print count+0 }
    ' "$ptx_file")

    local n_entries n_device_funcs
    n_entries=$(    grep -cE "^\.visible \.entry|^\.entry" "$ptx_file" 2>/dev/null || true); n_entries=${n_entries:-0}
    n_device_funcs=$(grep -cE "^\.visible \.func|^\.func"  "$ptx_file" 2>/dev/null || true); n_device_funcs=${n_device_funcs:-0}

    printf "  ptx_file=%s\n"              "$ptx_file"
    printf "  ptx_size_bytes=%s\n"        "$ptx_bytes"
    printf "  ptx_total_lines=%s\n"       "$ptx_lines"
    printf "  ptx_instruction_lines=%s\n" "$ptx_instr_lines"
    printf "  ptx_kernel_entries=%s\n"    "$n_entries"
    printf "  ptx_device_funcs=%s\n"      "$n_device_funcs"

    rm -f "$ptx_file"
}

cubin_analysis() {
    local cipher="$1" binary="$2"

    echo "[cubin cipher=$cipher]"

    if [ "$HAS_CUOBJDUMP" = false ]; then
        echo "  cuobjdump=not_available"
        return
    fi

    local bin_bytes
    bin_bytes=$(wc -c < "$binary" | tr -d ' ')
    printf "  binary_size_bytes=%s\n" "$bin_bytes"

    cuobjdump -elf "$binary" 2>/dev/null | awk '
        /Size/ && /\.text/ {
            if (match($0, /Size[[:space:]]+[0-9]+/)) {
                val = substr($0, RSTART, RLENGTH)
                sub(/Size[[:space:]]+/, "", val)
                if (val) printf "  cubin_text_bytes_%d=%s\n", NR, val
            }
        }
        /Size/ && /\.nv\.constant/ {
            if (match($0, /Size[[:space:]]+[0-9]+/)) {
                val = substr($0, RSTART, RLENGTH)
                sub(/Size[[:space:]]+/, "", val)
                if (val) printf "  cubin_const_bytes_%d=%s\n", NR, val
            }
        }
    ' || true

    local total_text total_const
    total_text=$(cuobjdump -elf "$binary" 2>/dev/null \
        | awk '/\.text/{for(i=1;i<=NF;i++) if($i~/^[0-9]+$/ && $i+0>16){sum+=$i+0;break}} END{print sum+0}')
    total_const=$(cuobjdump -elf "$binary" 2>/dev/null \
        | awk '/\.nv\.constant/{for(i=1;i<=NF;i++) if($i~/^[0-9]+$/){sum+=$i+0;break}} END{print sum+0}')

    printf "  cubin_total_text_bytes=%s\n"  "${total_text:-0}"
    printf "  cubin_total_const_bytes=%s\n" "${total_const:-0}"
}

constant_mem_layout() {
    local cipher="$1" src_dir="$2"

    echo "[constant_mem cipher=$cipher]"

    local kernel_files=()
    while IFS= read -r f; do
        kernel_files+=("$f")
    done < <(find "$src_dir" -maxdepth 3 \
        \( -name "${cipher}.cuh" -o -name "${cipher}.cu" \) \
        ! -name "${cipher}_*" 2>/dev/null | sort)

    if [ ${#kernel_files[@]} -eq 0 ]; then
        echo "  source_files=not_found"
        return
    fi

    awk '
        /^__constant__/ {
            line = $0
            sub(/^__constant__[[:space:]]+/, "", line)
            dims = ""; total = 1
            while (match(line, /\[[0-9]+\]/)) {
                num = substr(line, RSTART, RLENGTH)
                gsub(/[^0-9]/, "", num)
                dims = dims "[" num "]"
                total *= num
                sub(/\[[0-9]+\]/, "", line)
            }
            n = split(line, parts, /[[:space:];=]+/)
            type = parts[1]; name = parts[2]; gsub(/[;=]/, "", name)
            esize = "?"
            if (type ~ /uint8_t|int8_t|char/)     esize = 1
            if (type ~ /uint16_t|int16_t/)         esize = 2
            if (type ~ /uint32_t|int32_t|float/)   esize = 4
            if (type ~ /uint64_t|int64_t|double/)  esize = 8
            if (esize == "?")
                printf "  const_var=%-20s  type=%-10s  dims=%-12s  bytes=?\n", name, type, dims
            else {
                bytes = total * esize
                printf "  const_var=%-20s  type=%-10s  dims=%-12s  bytes=%d\n", name, type, dims, bytes
                total_bytes += bytes
            }
        }
        END { if (total_bytes) printf "  total_constant_declared_bytes=%d\n", total_bytes }
    ' "${kernel_files[@]}"

    awk '
        /^__device__/ { in_dev = 1 }
        /^__global__/ { in_dev = 0 }
        /^[a-zA-Z]/ && !/^__/ { in_dev = 0 }
        in_dev && match($0, /uint[0-9]+_t[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*\[[0-9]+\]/) {
            m = substr($0, RSTART, RLENGTH)
            split(m, arr, /[[:space:]\[\]]+/)
            type_str = arr[1]
            bits = type_str
            gsub(/[^0-9]/, "", bits)
            esize = bits / 8
            printf "  device_local_array=%-20s  type=%s  count=%-4s  bytes=%d\n", \
                arr[2], arr[1], arr[3], arr[3] * esize
        }
    ' "${kernel_files[@]}"
}

nsys_run() {
    local binary="$1" label="$2" out_dir="$3"; shift 3
    local out="${out_dir}/nsys_${label}"
    [ "$HAS_NSYS" = false ] && { echo ""; return; }

    local status=0
    nsys profile \
        --trace=cuda \
        --force-overwrite=true \
        -o "$out" \
        "$binary" "$@" >/dev/null 2>&1 || status=$?

    [ "$status" -eq 130 ] && { kill -INT $$; return; }

    nsys stats \
        --force-export=true \
        --report cudaapisum,gpukernsum,gpumemtimesum,gpumemsizesum \
        --format csv \
        "${out}.nsys-rep" > "${out}.txt" 2>/dev/null || true

    echo "${out}.txt"
}

parse_nsys() {
    local txt="$1"
    [ ! -f "$txt" ] && { echo "    nsys_log=missing"; return; }
    [ ! -s "$txt" ] && { echo "    nsys stats failed or generated empty report"; return; }

    python3 - "$txt" << 'EOF'
import csv, sys

try:
    with open(sys.argv[1], 'r', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        current_section = "Report"
        name_idx, val_idx = -1, -1
        val_header = ""

        for row in reader:
            if not row:
                continue
                
            if len(row) == 1:
                current_section = row[0].strip('": \n\r')
                name_idx, val_idx = -1, -1
                continue

            if any("Total Time" in c or "Duration" in c or "Total (" in c for c in row):
                name_idx = next((i for i, c in enumerate(row) if "Name" in c or "Operation" in c), -1)
                val_idx = next((i for i, c in enumerate(row) if "Total Time" in c or "Duration" in c or "Total (" in c), -1)
                if val_idx != -1:
                    val_header = row[val_idx].strip()
                continue

            if name_idx != -1 and val_idx != -1 and len(row) > max(name_idx, val_idx):
                name = str(row[name_idx]).strip("\"'\n\r ")
                val = str(row[val_idx]).strip("\"'\n\r ")

                if name and val and "Processing" not in name and "WARNING" not in name:
                    tag = "API"
                    if "Kernel" in current_section: tag = "Kernel"
                    elif "Memory Operation Time" in current_section: tag = "Mem Time"
                    elif "Memory Operation Size" in current_section: tag = "Mem Size"
                    short_name = (name[:45] + "...") if len(name) > 45 else name
                    if "Time" in val_header or "Duration" in val_header:
                        print(f"    [{tag:<8}] {short_name:<48} | {val_header}: {val} ns")
                    else:
                        print(f"    [{tag:<8}] {short_name:<48} | {val_header}: {val}")
except Exception as e:
    print(f"    [CSV Parse Error: {e}]")
EOF
}

static_analysis_cipher() {
    local cipher="$1"
    local out_dir="$RUNS_DIR/gpu/$cipher"
    mkdir -p "$out_dir"
    local out_file="$out_dir/static_analysis.txt"

    {
        printf "cipher=%s\n"      "$cipher"
        printf "timestamp=%s\n\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        local src_dir="$REPO_DIR/$cipher"
        [ -d "$src_dir" ] || src_dir="$REPO_DIR/src/$cipher"
        [ -d "$src_dir" ] || src_dir="$REPO_DIR"

        source_loc_analysis "$cipher"
        echo ""

        constant_mem_layout "$cipher" "$src_dir"
        echo ""

        local probe_mode=""
        for m in "${SUPPORTED_MODES[@]}"; do
            should_test_mode "$m" && { probe_mode="$m"; break; }
        done

        if [ -n "$probe_mode" ]; then
            local probe_target="${cipher}_${probe_mode}"
            local ptxas_log="$BUILD_DIR/ptxas_${probe_target}.log"
            build_target "$probe_target" "$ptxas_log" 2>/dev/null || true

            if [ -f "$BUILD_DIR/$probe_target" ]; then
                echo "[ptxas cipher=$cipher target=$probe_target]"
                if [ -s "$ptxas_log" ]; then
                    cat "$ptxas_log"
                else
                    echo "  not_captured"
                fi
                echo ""

                ptx_analysis "$cipher" "$probe_target"
                echo ""

                cubin_analysis "$cipher" "$BUILD_DIR/$probe_target"
                echo ""

                rm -f "$ptxas_log"
            fi
        fi

    } > "$out_file"

    echo "  static_analysis -> $out_file"
}

run_test() {
    local cipher="$1" mode="$2"
    local target="${cipher}_${mode}"
    local output_dir="$RUNS_DIR/gpu/$cipher/$mode"
    mkdir -p "$output_dir"
    local results_file="$output_dir/results.txt"
    local ptxas_log="$BUILD_DIR/ptxas_${target}.log"

    if ! build_target "$target" "$ptxas_log"; then
        echo "build_failed cipher=$cipher mode=$mode" | tee "$results_file"
        return 1
    fi

    if [ ! -f "$BUILD_DIR/$target" ]; then
        echo "binary_missing cipher=$cipher mode=$mode path=$BUILD_DIR/$target" | tee -a "$results_file"
        ls -la "$BUILD_DIR/" >> "$results_file" 2>&1 || true
        return 1
    fi

    {
        printf "cipher=%s mode=%s\n"   "$cipher" "$mode"
        printf "binary=%s\n"           "$BUILD_DIR/$target"
        printf "timestamp=%s\n"        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf "profile=%s\n\n"        "$PROFILE"
    } > "$results_file"

    write_cpu_info "$results_file"

    {
        echo "[ptxas cipher=$cipher mode=$mode]"
        if [ -s "$ptxas_log" ]; then
            cat "$ptxas_log"
        else
            echo "  not_captured"
        fi
        echo ""

        echo "[parallelism cipher=$cipher mode=$mode]"
        case "$cipher-$mode" in
            present-cbc) echo "  encrypt=sequential_1block_1thread  decrypt=parallel_multi_stream" ;;
            *-cbc)       echo "  encrypt=sequential  decrypt=parallel_multi_stream" ;;
            *-ctr)       echo "  encrypt=parallel  decrypt=parallel" ;;
        esac
        echo ""
    } >> "$results_file"

    rm -f "$ptxas_log"

    echo "[results cipher=$cipher mode=$mode]" >> "$results_file"
    printf "%-42s  %-6s  %-12s  %-12s  %-12s  %-12s  %s\n" \
    "file" "status" "enc_time" "enc_tput" "dec_time" "dec_tput" "verify" \
    >> "$results_file"

    local gpu_info_written=false

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
            
            local enc_nsys_cmd=("$BUILD_DIR/$target" "-e" "$plaintext_path" "$key" "$iv" "${encrypted_file}.nsys_tmp")
            if [ "$mode" = "ctr" ]; then
                enc_cmd+=("--nopad")
                dec_cmd+=("--nopad")
                enc_nsys_cmd+=("--nopad")
            fi
    
            local enc_stdout_file="$output_dir/${test_name}.enc.out"
            local enc_result enc_status enc_ms
            enc_result=$(time_command "$enc_stdout_file" "${enc_cmd[@]}")
            enc_status=${enc_result%% *}; enc_ms=${enc_result#* }
            
            if [ "$enc_status" -ne 0 ]; then
                {
                    printf "%-42s  FAIL    enc_failed (exit=%s)\n" "$plaintext_file" "$enc_status"
                    printf "  binary=%s  exists=%s  executable=%s\n" \
                        "$BUILD_DIR/$target" \
                        "$([ -f "$BUILD_DIR/$target" ] && echo yes || echo no)" \
                        "$([ -x "$BUILD_DIR/$target" ] && echo yes || echo no)"
                    if [ -s "$enc_stdout_file" ]; then
                        printf "  [cuda_output op=encrypt]\n"
                        strip_gpu_info < "$enc_stdout_file" | sed 's/^/    /'
                    else
                        printf "  [cuda_output op=encrypt] (empty)\n"
                    fi
                } | tee -a "$results_file"
                rm -f "$enc_stdout_file"
                continue
            fi
            local enc_tput; enc_tput=$(throughput_str "$file_bytes" "$enc_ms")
    
            if [ "$gpu_info_written" = false ] && [ -s "$enc_stdout_file" ]; then
                local gpu_block
                gpu_block=$(awk '
                    /\[gpu_info\]/ { in_block=1 }
                    in_block { print }
                    in_block && /^[[:space:]]*[0-9]+[[:space:]]+/ { in_block=0 }
                ' "$enc_stdout_file")
                if [ -n "$gpu_block" ]; then
                    printf "%s\n\n" "$gpu_block" >> "$results_file"
                fi
                gpu_info_written=true
            fi
    
            local dec_stdout_file="$output_dir/${test_name}.dec.out"
            local dec_result dec_status dec_ms
            dec_result=$(time_command "$dec_stdout_file" "${dec_cmd[@]}")
            dec_status=${dec_result%% *}; dec_ms=${dec_result#* }
            
            if [ "$dec_status" -ne 0 ]; then
                {
                    printf "%-42s  FAIL    dec_failed\n" "$plaintext_file"
                    if [ -s "$dec_stdout_file" ]; then
                        printf "  [cuda_output op=decrypt]\n"
                        strip_gpu_info < "$dec_stdout_file" | sed 's/^/    /'
                    fi
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
    
            if [ -s "$enc_stdout_file" ] || [ -s "$dec_stdout_file" ]; then
                {
                    if [ -s "$enc_stdout_file" ]; then
                        printf "  [cuda_output op=encrypt file=%s]\n" "$plaintext_file"
                        strip_gpu_info < "$enc_stdout_file" | sed 's/^/    /'
                    fi
                    if [ -s "$dec_stdout_file" ]; then
                        printf "  [cuda_output op=decrypt file=%s]\n" "$plaintext_file"
                        strip_gpu_info < "$dec_stdout_file" | sed 's/^/    /'
                    fi
                } >> "$results_file"
            fi
    
            rm -f "$encrypted_file" "$decrypted_file" "$enc_stdout_file" "$dec_stdout_file"
    
            if [ "$PROFILE" = true ]; then
                local nsys_log
                nsys_log=$(nsys_run "${enc_nsys_cmd[0]}" "${test_name}_enc" "$output_dir" "${enc_nsys_cmd[@]:1}")
                rm -f "${encrypted_file}.nsys_tmp"
                if [ -n "$nsys_log" ]; then
                    {
                        printf "  [nsys file=%s op=encrypt]\n" "$plaintext_file"
                        parse_nsys "$nsys_log"
                    } >> "$results_file"
                    local nsys_base="${nsys_log%.txt}"
                    rm -f "$nsys_log" "${nsys_base}.nsys-rep" "${nsys_base}.sqlite"
                fi
            fi
            
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