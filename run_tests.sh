#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPU_RUNNER="$REPO_DIR/cpu/run_tests.sh"
GPU_RUNNER="$REPO_DIR/gpu/run_tests.sh"

BACKEND="all"
ARGS=()

usage() {
    cat <<EOF
Usage: $0 [options] [-- <nested options>]

Options:
  --backend <cpu|gpu|all>   Choose which backend to run (default: all)
  --help                    Show this help message

All other flags are forwarded to the nested CPU and GPU runners.
Examples:
  $0 --cipher present --mode ctr
  $0 --backend gpu -- --cipher gift --mode cbc
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backend)
            BACKEND="${2,,}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            ARGS+=("$@")
            break
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

run_backend() {
    local backend="$1"
    local runner="$2"

    if [ "$BACKEND" = "all" ] || [ "$BACKEND" = "$backend" ]; then
        echo "Running $backend tests"
        bash "$runner" "${ARGS[@]}"
        echo ""
    fi
}

if [ "$BACKEND" != "all" ] && [ "$BACKEND" != "cpu" ] && [ "$BACKEND" != "gpu" ]; then
    echo "Unknown backend: $BACKEND" >&2
    usage
    exit 1
fi

run_backend cpu "$CPU_RUNNER"
run_backend gpu "$GPU_RUNNER"

echo "All requested tests completed."
