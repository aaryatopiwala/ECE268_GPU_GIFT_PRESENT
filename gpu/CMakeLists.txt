cmake_minimum_required(VERSION 3.18)
project(cuda-ciphers LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

add_compile_options(
    "$<$<COMPILE_LANGUAGE:CUDA>:-lineinfo;--use_fast_math>"
    "$<$<COMPILE_LANGUAGE:CXX>:-O3;-Wall;-g>"
)

TRY_RUN(
    FIND_GPU_RESULT
    FIND_GPU_COMPILE_RESULT
    ${CMAKE_CURRENT_BINARY_DIR}/
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/findgpu.cu
    RUN_OUTPUT_VARIABLE GPU_ARCH_OUTPUT
)

if(FIND_GPU_COMPILE_RESULT AND (FIND_GPU_RESULT EQUAL 0) AND GPU_ARCH_OUTPUT)
    message(STATUS "GPU detected — targeting architecture: sm_${GPU_ARCH_OUTPUT}")
    set(CMAKE_CUDA_ARCHITECTURES ${GPU_ARCH_OUTPUT})
else()
    message(STATUS "No GPU detected — compiling for: 70 75 80 86 89 90")
    set(CMAKE_CUDA_ARCHITECTURES 70 75 80 86 89 90)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)

macro(add_cipher_target name source cipher_dir)
    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/${cipher_dir}/${source})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/${cipher_dir}  
        ${CMAKE_CURRENT_SOURCE_DIR}/utils
    )
endmacro()

add_cipher_target(present_cbc present_cbc.cu present)
add_cipher_target(present_ctr present_ctr.cu present)

add_cipher_target(gift_cbc gift_cbc.cu gift)
add_cipher_target(gift_ctr gift_ctr.cu gift)