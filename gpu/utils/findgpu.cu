#include <iostream>
#include <cuda_runtime.h>

int main() {
    int device;
    cudaDeviceProp prop;
    if (cudaGetDevice(&device) != cudaSuccess) return 1;
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) return 1;
    std::cout << prop.major << prop.minor;
    
    return 0;
}