#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA_DIR="$REPO_DIR/test_data"
GPU_RUN_SCRIPT="$REPO_DIR/gpu/run.sh"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "Running GPU cipher tests..."

run_present_tests() {
    local cipher="present"
    local test_data_path="$TEST_DATA_DIR/$cipher"
    
    if [ ! -d "$test_data_path" ]; then
        echo "ERROR: Test data directory for $cipher not found at $test_data_path"
        return 1
    fi
    
    echo ""
    echo "PRESENT Tests"
    
    # CTR Mode Tests
    echo ""
    echo "--- PRESENT CTR Mode ---"
    for vector_dir in "$test_data_path"/vector_*; do
        if [ -d "$vector_dir" ]; then
            vector_name=$(basename "$vector_dir")
            plaintext_file="$vector_dir/plaintext.bin"
            key_file="$vector_dir/key.bin"
            ciphertext_file="$vector_dir/ciphertext.bin"
            
            if [ ! -f "$plaintext_file" ] || [ ! -f "$key_file" ] || [ ! -f "$ciphertext_file" ]; then
                echo "WARNING: Missing test files in $vector_dir, skipping"
                continue
            fi
            
            # Convert binary files to hex
            key_hex=$(xxd -p -c 256 "$key_file")
            iv_hex="0000000000000000"  # Null IV for CTR mode
            
            encrypted_output="$TEMP_DIR/${vector_name}_encrypted.bin"
            decrypted_output="$TEMP_DIR/${vector_name}_decrypted.bin"
            
            # Test encryption
            echo -n "  Testing $vector_name encryption... "
            "$GPU_RUN_SCRIPT" \
                --cipher "$cipher" \
                --mode ctr \
                --encrypt \
                --input "$plaintext_file" \
                --key "$key_hex" \
                --iv "$iv_hex" \
                --output "$encrypted_output"
            
            # Compare encrypted output with expected ciphertext
            if cmp -s "$encrypted_output" "$ciphertext_file"; then
                echo "PASS"
            else
                echo "FAIL"
                echo "    Expected ciphertext: $(xxd -p "$ciphertext_file")"
                echo "    Got:                 $(xxd -p "$encrypted_output")"
            fi
            
            # Test decryption
            echo -n "  Testing $vector_name decryption... "
            "$GPU_RUN_SCRIPT" \
                --cipher "$cipher" \
                --mode ctr \
                --decrypt \
                --input "$ciphertext_file" \
                --key "$key_hex" \
                --iv "$iv_hex" \
                --output "$decrypted_output"
            
            # Compare decrypted output with original plaintext
            if cmp -s "$decrypted_output" "$plaintext_file"; then
                echo "PASS"
            else
                echo "FAIL"
                echo "    Expected plaintext: $(xxd -p "$plaintext_file")"
                echo "    Got:                $(xxd -p "$decrypted_output")"
            fi
        fi
    done
    
    # CBC Mode Tests
    # echo ""
    # echo "--- PRESENT CBC Mode ---"
    # for vector_dir in "$test_data_path"/vector_*; do
    #     if [ -d "$vector_dir" ]; then
    #         vector_name=$(basename "$vector_dir")
    #         plaintext_file="$vector_dir/plaintext.bin"
    #         key_file="$vector_dir/key.bin"
    #         ciphertext_file="$vector_dir/ciphertext.bin"
    #         
    #         if [ ! -f "$plaintext_file" ] || [ ! -f "$key_file" ] || [ ! -f "$ciphertext_file" ]; then
    #             echo "WARNING: Missing test files in $vector_dir, skipping"
    #             continue
    #         fi
    #         
    #         # Convert binary files to hex
    #         key_hex=$(xxd -p -c 256 "$key_file")
    #         iv_hex="0000000000000000"  # Null IV for testing
    #         
    #         encrypted_output="$TEMP_DIR/${vector_name}_cbc_encrypted.bin"
    #         decrypted_output="$TEMP_DIR/${vector_name}_cbc_decrypted.bin"
    #         
    #         # Test encryption
    #         echo -n "  Testing $vector_name encryption... "
    #         "$GPU_RUN_SCRIPT" \
    #             --cipher "$cipher" \
    #             --mode cbc \
    #             --encrypt \
    #             --input "$plaintext_file" \
    #             --key "$key_hex" \
    #             --iv "$iv_hex" \
    #             --output "$encrypted_output"
    #         
    #         # Compare encrypted output with expected ciphertext
    #         if cmp -s "$encrypted_output" "$ciphertext_file"; then
    #             echo "PASS"
    #         else
    #             echo "FAIL"
    #         fi
    #         
    #         # Test decryption
    #         echo -n "  Testing $vector_name decryption... "
    #         "$GPU_RUN_SCRIPT" \
    #             --cipher "$cipher" \
    #             --mode cbc \
    #             --decrypt \
    #             --input "$ciphertext_file" \
    #             --key "$key_hex" \
    #             --iv "$iv_hex" \
    #             --output "$decrypted_output"
    #         
    #         # Compare decrypted output with original plaintext
    #         if cmp -s "$decrypted_output" "$plaintext_file"; then
    #             echo "PASS"
    #         else
    #             echo "FAIL"
    #         fi
    #     fi
    # done
}

# run_gift_tests() {
#     local cipher="gift"
#     local test_data_path="$TEST_DATA_DIR/$cipher"
#     
#     if [ ! -d "$test_data_path" ]; then
#         echo "WARNING: Test data directory for $cipher not found at $test_data_path"
#         return 0
#     fi
#     
#     # CTR Mode Tests (commented out)
#     # echo ""
#     # echo "--- GIFT CTR Mode ---"
#     # for vector_dir in "$test_data_path"/vector_*; do
#     #     ...
#     # done
#     
#     # CBC Mode Tests (commented out)
#     # echo ""
#     # echo "--- GIFT CBC Mode ---"
#     # for vector_dir in "$test_data_path"/vector_*; do
#     #     ...
#     # done
# }

# run_aes_tests() {
#     local cipher="aes"
#     local test_data_path="$TEST_DATA_DIR/$cipher"
#     
#     if [ ! -d "$test_data_path" ]; then
#         echo "WARNING: Test data directory for $cipher not found at $test_data_path"
#         return 0
#     fi
#     
#     
#     # CTR Mode Tests (commented out)
#     # echo ""
#     # echo "--- AES CTR Mode ---"
#     # for vector_dir in "$test_data_path"/vector_*; do
#     #     ...
#     # done
#     
#     # CBC Mode Tests (commented out)
#     # echo ""
#     # echo "--- AES CBC Mode ---"
#     # for vector_dir in "$test_data_path"/vector_*; do
#     #     ...
#     # done
# }

run_present_tests
# run_gift_tests
# run_aes_tests

echo ""
echo "All tests completed!"
