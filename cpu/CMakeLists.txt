cmake_minimum_required(VERSION 3.18)
project(cpu-ciphers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Link Time Optimization (-flto) natively via CMake
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)
if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Apply optimization flags from the old Makefiles (for GCC/Clang)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-O3 -ffast-math -funroll-loops -Wall)
    
    # Handle the macOS/Apple Silicon vs Linux/Windows architecture flag
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        add_compile_options(-mcpu=native)
    else()
        add_compile_options(-march=native)
    endif()
endif()

# Include global utilities if applicable (uncomment if needed)
# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)

macro(add_cpu_cipher_target name source cipher_dir)
    # Using .cpp instead of .cu for the CPU targets
    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/${cipher_dir}/${source})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/${cipher_dir}
        # ${CMAKE_CURRENT_SOURCE_DIR}/utils
    )
endmacro()

# Present targets
add_cpu_cipher_target(present_cbc present_cbc.cpp present)
add_cpu_cipher_target(present_ctr present_ctr.cpp present)

# GIFT targets
add_cpu_cipher_target(gift_cbc gift_cbc.cpp gift)
add_cpu_cipher_target(gift_ctr gift_ctr.cpp gift)

# AES targets
add_cpu_cipher_target(aes_cbc aes_cbc.cpp aes)
add_cpu_cipher_target(aes_ctr aes_ctr.cpp aes)