#include "../utils/gpu_info.cuh"
#include "../utils/gpu_transfer.cuh"
#include "../utils/timer.hpp"

__global__ void encryptCBCBuffer(float* data, int n) {
    int gs = gridDim.x;
    int bs = blockDim.x;
    int bx = blockIdx.x;
    int tx = threadIdx.x;
    int i = bx * bs + tx;
    if (i < n) data[i] *= data[i]; // TODO
}

__global__ void decryptCBCBuffer(float* data, int n) {
    int gs = gridDim.x;
    int bs = blockDim.x;
    int bx = blockIdx.x;
    int tx = threadIdx.x;
    int i = bx * bs + tx;
    if (i < n) data[i] *= data[i]; // TODO
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
        ScopedTimer kt("encryptCBCBuffer");             // prints on scope exit
        encryptCBCBuffer<<<1, 256>>>(d_data, h_data.size());
        cudaDeviceSynchronize();
    }

    // Download results back to host
    std::vector<float> h_result = gpuTransferToHost(d_data, h_data.size());
    printf("Total: %ld ms\n", t.stopMs());
    cudaFree(d_data);
    for (float v : h_result) printf("%.0f ", v);
}