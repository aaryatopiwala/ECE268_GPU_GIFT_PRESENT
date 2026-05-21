#include "gpu_info.cuh"
#include "gpu_transfer.cuh"
#include "timer.hpp"

__global__ void squareKernel(float* data, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) data[i] *= data[i];
}

int main() {
    // Detect GPU
    if (!gpuIsAvailable()) {
        fprintf(stderr, "No CUDA devices found.\n");
        return 1;
    }
    gpuPrintProperties();                // print summary table to stdout
    int dev = gpuSelectBestDevice();     // pick highest-memory GPU, set active

    // Prepare data on host
    std::vector<float> h_data = {1, 2, 3, 4, 5};

    // Upload data to GPU
    Timer t;
    t.start();
    float* d_data = gpuTransferToDevice(h_data);
    printf("Upload: %ld ms\n", t.lapMs());

    // Kernel launch with timing
    {
        ScopedTimer kt("squareKernel");             // prints on scope exit
        squareKernel<<<1, 256>>>(d_data, h_data.size());
        cudaDeviceSynchronize();
    }

    // Download results back to host
    std::vector<float> h_result = gpuTransferToHost(d_data, h_data.size());
    printf("Total: %ld ms\n", t.stopMs());
    cudaFree(d_data);
    for (float v : h_result) printf("%.0f ", v);
}