import zipfile

data = [
    ("0000000000000000", "00000000000000000000", "5579C1387B228445"),
    ("0000000000000000", "FFFFFFFFFFFFFFFFFFFF", "E72C46C0F5945049"),
    ("FFFFFFFFFFFFFFFF", "00000000000000000000", "A112FFC72F68417B"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFF", "3333DCD3213210D2"),
]

zip_filename = "crypto_binaries.zip"
with zipfile.ZipFile(zip_filename, 'w') as zf:
    for i, (pt_hex, key_hex, ct_hex) in enumerate(data, 1):
        pt_bytes = bytes.fromhex(pt_hex)
        key_bytes = bytes.fromhex(key_hex)
        ct_bytes = bytes.fromhex(ct_hex)

        zf.writestr(f"vector_{i}/plaintext.bin", pt_bytes)
        zf.writestr(f"vector_{i}/key.bin", key_bytes)
        zf.writestr(f"vector_{i}/ciphertext.bin", ct_bytes)

print(f"Successfully created {zip_filename} in the current directory.")