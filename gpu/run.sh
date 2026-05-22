#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$REPO_DIR/build"

CIPHER=""
MODE=""
RUN_MODE="run"
OP=""
INPUT=""
KEY=""
IV=""
OUTPUT=""
NOPAD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --cipher)   CIPHER="${2,,}";   shift 2 ;;
        --mode)     MODE="${2,,}";     shift 2 ;;
        --run-mode) RUN_MODE="${2,,}"; shift 2 ;;
        --build-only) RUN_MODE="build"; shift ;;
        --encrypt)  OP="-e";           shift ;;
        --decrypt)  OP="-d";           shift ;;
        --input)    INPUT="$2";        shift 2 ;;
        --key)      KEY="$2";          shift 2 ;;
        --iv)       IV="$2";           shift 2 ;;
        --output)   OUTPUT="$2";       shift 2 ;;
        --nopad)    NOPAD="--nopad";   shift ;;
        --help|-h)
            echo "Usage: $0 --cipher <present|gift> --mode <cbc|ctr> --encrypt|--decrypt --input <file> --key <hex> --iv <hex> --output <file> [--nopad] [--run-mode <run|sanitize|profile>]"
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
cmake "$REPO_DIR" -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

[ "$RUN_MODE" = "build" ] && exit 0

if [ -z "$CIPHER" ] || [ -z "$MODE" ]; then
    echo "ERROR: --cipher and --mode are required" >&2; exit 1
fi
if [[ "$CIPHER" != "present" && "$CIPHER" != "gift" ]]; then
    echo "ERROR: --cipher must be 'present' or 'gift'" >&2; exit 1
fi
if [[ "$MODE" != "cbc" && "$MODE" != "ctr" ]]; then
    echo "ERROR: --mode must be 'cbc' or 'ctr'" >&2; exit 1
fi
if [ -z "$OP" ] || [ -z "$INPUT" ] || [ -z "$KEY" ] || [ -z "$IV" ] || [ -z "$OUTPUT" ]; then
    echo "ERROR: --encrypt|--decrypt, --input, --key, --iv, and --output are required" >&2; exit 1
fi

TARGET="./${CIPHER}_${MODE}"
CMD="$TARGET $OP $INPUT $KEY $IV $OUTPUT $NOPAD"

case $RUN_MODE in
    run)      $CMD ;;
    sanitize) compute-sanitizer $CMD ;;
    profile)
        nsys profile --output="${BUILD_DIR}/${CIPHER}_${MODE}_profile" \
            --stats=true --force-overwrite=true $CMD ;;
    *) echo "ERROR: unknown --run-mode '$RUN_MODE'" >&2; exit 1 ;;
esac