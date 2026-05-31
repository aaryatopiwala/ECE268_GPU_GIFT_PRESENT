# GPU-Accelerated PRESENT-80 and GIFT-128 Block Ciphers

Pranav Mehta (A17323782), Aarya Topiwala (A17295542), Diyou (Dill) Wang (A17118730)

## Repository Structure

```text
├── README.md
├── run.sh                 # Single script to test both CPU and GPU implementations
├── tests/              # Directory for test files
│
├── cpu/                       # CPU implementations directory
│   ├── CMakeLists.txt
│   ├── README.md
│   ├── run_cpu.sh             # Runner script for CPU validation and benchmarking
│   ├── present/
│   │   ├── present.hpp        # Shared logic: key schedule, encryption, decryption
│   │   ├── present_ctr.cpp    # CTR mode wrapper for PRESENT
│   │   └── present_cbc.cpp    # CBC mode wrapper for PRESENT
│   │
│   ├── gift/
│   │   ├── gift.hpp           # Shared logic: key schedule, encryption, decryption
│   │   ├── gift_ctr.cpp       # CTR mode wrapper for GIFT
│   │   └── gift_cbc.cpp       # CBC mode wrapper for GIFT
│   │
│   └── aes/
│       ├── aes.hpp            # Shared logic: key schedule, encryption, decryption
│       ├── aes_ctr.cpp        # CTR mode wrapper for AES
│       └── aes_cbc.cpp        # CBC mode wrapper for AES
│
└── gpu/                       # GPU implementations directory
    ├── CMakeLists.txt
    ├── README.md
    ├── run_gpu.sh             # Runner script for GPU validation and benchmarking
    ├── utils/                 # Useful GPU setup, timing, and T table generation tools 
    │
    ├── present/
    │   ├── present.cuh        # Shared logic: key schedule, encryption, decryption
    │   ├── present_ctr.cu     # CTR mode wrapper for PRESENT
    │   └── present_cbc.cu     # CBC mode wrapper for PRESENT
    │
    ├── gift/
    │   ├── gift.cuh           # Shared logic: key schedule, encryption, decryption
    │   ├── gift_ctr.cu        # CTR mode wrapper for GIFT
    │   └── gift_cbc.cu        # CBC mode wrapper for GIFT
    │
    └── aes/
        ├── aes.cuh            # Shared logic: key schedule, encryption, decryption
        ├── aes_ctr.cu         # CTR mode wrapper for AES
        └── aes_cbc.cu         # CBC mode wrapper for AES
```

## Compilation (CPU)

1. ```cd``` into the ```cpu``` directory
2. Read the cpu [README](cpu/README.md) for more info

## Compilation (GPU)

1. ```cd``` into the ```gpu``` directory
2. Read the gpu [README](gpu/README.md) for more info

## Testing

1. Run ```run.sh``` in root directory or ```cd``` into subdirectories like ```gpu``` or ```cpu```
3. Run ```python3 tests/gen_test_file.py ouput <--b|--kb|--mb|--gb> size``` to generate more test files with specified size and units.