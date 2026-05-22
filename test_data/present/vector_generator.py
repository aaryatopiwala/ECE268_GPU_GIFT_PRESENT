import os

data = [
    ("0000000000000000", "00000000000000000000", "5579C1387B228445"),
    ("0000000000000000", "FFFFFFFFFFFFFFFFFFFF", "E72C46C0F5945049"),
    ("FFFFFFFFFFFFFFFF", "00000000000000000000", "A112FFC72F68417B"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFF", "3333DCD3213210D2"),
]

for i, (pt_hex, key_hex, ct_hex) in enumerate(data, 1):
    pt_bytes = bytes.fromhex(pt_hex)
    key_bytes = bytes.fromhex(key_hex)
    ct_bytes = bytes.fromhex(ct_hex)

    dir_name = f"vector_{i}"
    os.makedirs(dir_name, exist_ok=True)

    with open(os.path.join(dir_name, "plaintext.bin"), "wb") as f:
        f.write(pt_bytes)
        
    with open(os.path.join(dir_name, "key.bin"), "wb") as f:
        f.write(key_bytes)
        
    with open(os.path.join(dir_name, "ciphertext.bin"), "wb") as f:
        f.write(ct_bytes)

print("Successfully created test vectors!")