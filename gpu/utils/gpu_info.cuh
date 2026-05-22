#pragma once
#include <cstdio>
#include <cuda_runtime.h>

/**
 * Structured representation of a single CUDA device's properties.
 */
struct GpuInfo {
    int    deviceIndex;
    char   name[256];
    size_t totalGlobalMemBytes;   // Total global memory in bytes
    int    computeCapabilityMajor;
    int    computeCapabilityMinor;
    int    multiprocessorCount;
    int    maxThreadsPerBlock;
    int    warpSize;
    int    memoryClockRateKHz;
    int    memoryBusWidthBits;
    double peakBandwidthGBs;      // Computed: 2 * clockKHz * (busWidth/8) / 1e6
};

static inline bool _gpuCheck(cudaError_t err, const char* context) {
    if (err != cudaSuccess) {
        fprintf(stderr, "[gpu_info] CUDA error in %s: %s (%s)\n",
                context, cudaGetErrorString(err), cudaGetErrorName(err));
        return false;
    }
    return true;
}

/**
 * Returns true if at least one CUDA-capable device is present and accessible.
 * Safe to call before any other CUDA API.
 */
inline bool gpuIsAvailable() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return (err == cudaSuccess) && (count > 0);
}

/**
 * Returns the number of available CUDA devices.
 * Returns 0 on error or if none are present.
 */
inline int gpuDeviceCount() {
    int count = 0;
    cudaGetDeviceCount(&count);
    return count;
}

/**
 * Fills and returns a GpuInfo struct for the given device index.
 * Returns a zeroed struct (deviceIndex == -1) on failure.
 */
inline GpuInfo gpuGetInfo(int deviceIndex) {
    GpuInfo info{};
    info.deviceIndex = -1;

    cudaDeviceProp prop{};
    if (!_gpuCheck(cudaGetDeviceProperties(&prop, deviceIndex), "cudaGetDeviceProperties"))
        return info;

    info.deviceIndex            = deviceIndex;
    info.totalGlobalMemBytes    = prop.totalGlobalMem;
    info.computeCapabilityMajor = prop.major;
    info.computeCapabilityMinor = prop.minor;
    info.multiprocessorCount    = prop.multiProcessorCount;
    info.maxThreadsPerBlock     = prop.maxThreadsPerBlock;
    info.warpSize               = prop.warpSize;
    info.memoryClockRateKHz     = prop.memoryClockRate;
    info.memoryBusWidthBits     = prop.memoryBusWidth;
    info.peakBandwidthGBs       = 2.0 * prop.memoryClockRate
                                       * (prop.memoryBusWidth / 8.0)
                                       / 1.0e6;
    // Copy name safely
    snprintf(info.name, sizeof(info.name), "%s", prop.name);
    return info;
}

/**
 * Prints a formatted summary of all detected CUDA devices to stdout.
 * Reports: index, name, memory, compute capability, SMs, peak bandwidth.
 */
inline void gpuPrintProperties() {
    int nDevices = gpuDeviceCount();
    if (nDevices == 0) {
        fprintf(stdout, "[gpu_info] No CUDA-capable devices found.\n");
        return;
    }

    fprintf(stdout, "[gpu_info] Found %d CUDA device(s):\n", nDevices);
    fprintf(stdout, "  %-4s  %-30s  %-10s  %-6s  %-5s  %-7s  %s\n",
            "Dev", "Name", "Mem (MB)", "CC", "SMs", "Warps", "Peak BW (GB/s)");
    fprintf(stdout, "  %s\n", std::string(80, '-').c_str());

    for (int i = 0; i < nDevices; ++i) {
        GpuInfo info = gpuGetInfo(i);
        if (info.deviceIndex < 0) continue;

        fprintf(stdout, "  %-4d  %-30s  %-10.0f  %d.%-4d  %-5d  %-7d  %.2f\n",
                info.deviceIndex,
                info.name,
                info.totalGlobalMemBytes / (1024.0 * 1024.0),
                info.computeCapabilityMajor,
                info.computeCapabilityMinor,
                info.multiprocessorCount,
                info.warpSize,
                info.peakBandwidthGBs);
    }
}

/**
 * Selects the device with the most global memory and sets it as active.
 * Returns the chosen device index, or -1 on failure.
 * Useful when multiple GPUs are present and you want the beefiest one.
 */
inline int gpuSelectBestDevice() {
    int nDevices = gpuDeviceCount();
    if (nDevices == 0) return -1;

    int    bestDev = 0;
    size_t bestMem = 0;
    for (int i = 0; i < nDevices; ++i) {
        GpuInfo info = gpuGetInfo(i);
        if (info.deviceIndex >= 0 && info.totalGlobalMemBytes > bestMem) {
            bestMem = info.totalGlobalMemBytes;
            bestDev = i;
        }
    }

    if (!_gpuCheck(cudaSetDevice(bestDev), "cudaSetDevice"))
        return -1;

    return bestDev;
}
