import os

# GIFT128 Test Vectors
data = [
    ("00000000000000000000000000000000", "00000000000000000000000000000000", "cd0bd738388ad3f668b15a36ceb6ff92"),
    ("fedcba9876543210fedcba9876543210", "fedcba9876543210fedcba9876543210", "8422241a6dbf5a9346af468409ee0152"),
    ("e39c141fa57dba43f08a85b6a91f86c1", "d0f5c59a7700d3e799028fa9f90ad837", "13ede67cbdcc3dbf400a62d6977265ea")
]

for i, (pt_hex, key_hex, ct_hex) in enumerate(data, 1):
    pt_bytes = bytes.fromhex(pt_hex)
    key_bytes = bytes.fromhex(key_hex)
    ct_bytes = bytes.fromhex(ct_hex)

    dir_name = f"vector_{i}"
    os.makedirs(dir_name, exist_ok=True)

    # Write the binary files into the corresponding directory
    with open(os.path.join(dir_name, "plaintext.bin"), "wb") as f:
        f.write(pt_bytes)
        
    with open(os.path.join(dir_name, "key.bin"), "wb") as f:
        f.write(key_bytes)
        
    with open(os.path.join(dir_name, "ciphertext.bin"), "wb") as f:
        f.write(ct_bytes)

print("Successfully created test vectors!")