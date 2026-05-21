#pragma once
#include <vector>
#include <cstdio>
#include <cuda_runtime.h>
#include <stdexcept>

namespace _gpu_transfer_detail {

inline void handleError(cudaError_t err, const char* context) {
    if (err == cudaSuccess) return;
    fprintf(stderr, "[gpu_transfer] CUDA error in %s: %s (%s)\n",
            context, cudaGetErrorString(err), cudaGetErrorName(err));
#ifndef GPU_TRANSFER_NO_THROW
    throw std::runtime_error(std::string("[gpu_transfer] ") + cudaGetErrorString(err));
#endif
}

}

/**
 * Copies `count` elements of type T from a device pointer into a newly
 * allocated std::vector<T> and returns it.
 *
 * Equivalent to the original transferTB2Host() but generic.
 *
 * @param d_ptr   Device pointer to the source buffer.
 * @param count   Number of T elements to copy.
 * @return        std::vector<T> of size `count` containing the device data.
 *                Returns an empty vector on error (if GPU_TRANSFER_NO_THROW).
 */
template <typename T>
std::vector<T> gpuTransferToHost(const T* d_ptr, size_t count) {
    if (!d_ptr || count == 0) return {};

    std::vector<T> h_buf(count);
    cudaError_t err = cudaMemcpy(
        h_buf.data(),
        d_ptr,
        count * sizeof(T),
        cudaMemcpyDeviceToHost
    );
    _gpu_transfer_detail::handleError(err, "gpuTransferToHost / cudaMemcpy");

#ifdef GPU_TRANSFER_NO_THROW
    if (err != cudaSuccess) return {};
#endif

    return h_buf;
}

/**
 * Allocates a device buffer large enough for `h_data`, copies the contents
 * into it, and returns the device pointer.
 *
 * Caller is responsible for calling cudaFree() on the returned pointer.
 *
 * @param h_data  Source data on the host.
 * @return        Device pointer (T*) to the uploaded buffer, or nullptr on error.
 */
template <typename T>
T* gpuTransferToDevice(const std::vector<T>& h_data) {
    if (h_data.empty()) return nullptr;

    T* d_ptr = nullptr;
    cudaError_t err = cudaMalloc(reinterpret_cast<void**>(&d_ptr),
                                 h_data.size() * sizeof(T));
    _gpu_transfer_detail::handleError(err, "gpuTransferToDevice / cudaMalloc");
#ifdef GPU_TRANSFER_NO_THROW
    if (err != cudaSuccess) return nullptr;
#endif

    err = cudaMemcpy(d_ptr, h_data.data(),
                     h_data.size() * sizeof(T),
                     cudaMemcpyHostToDevice);
    _gpu_transfer_detail::handleError(err, "gpuTransferToDevice / cudaMemcpy");
#ifdef GPU_TRANSFER_NO_THROW
    if (err != cudaSuccess) { cudaFree(d_ptr); return nullptr; }
#endif

    return d_ptr;
}

/**
 * Copies host vector data into an *existing* device buffer.
 * Does NOT allocate — the device buffer must already be large enough.
 *
 * @param h_data  Source data.
 * @param d_ptr   Pre-allocated device destination.
 * @return        true on success, false on error.
 */
template <typename T>
bool gpuUpload(const std::vector<T>& h_data, T* d_ptr) {
    if (!d_ptr || h_data.empty()) return false;

    cudaError_t err = cudaMemcpy(d_ptr, h_data.data(),
                                 h_data.size() * sizeof(T),
                                 cudaMemcpyHostToDevice);
    _gpu_transfer_detail::handleError(err, "gpuUpload / cudaMemcpy");
    return (err == cudaSuccess);
}

/**
 * Copies `count` elements from a device pointer into an existing host vector.
 * The vector is resized to `count` before copying.
 *
 * @param d_ptr   Source device pointer.
 * @param count   Number of T elements to copy.
 * @param h_buf   Destination vector (will be resized).
 * @return        true on success, false on error.
 */
template <typename T>
bool gpuDownload(const T* d_ptr, size_t count, std::vector<T>& h_buf) {
    if (!d_ptr || count == 0) return false;

    h_buf.resize(count);
    cudaError_t err = cudaMemcpy(h_buf.data(), d_ptr,
                                 count * sizeof(T),
                                 cudaMemcpyDeviceToHost);
    _gpu_transfer_detail::handleError(err, "gpuDownload / cudaMemcpy");
    return (err == cudaSuccess);
}
