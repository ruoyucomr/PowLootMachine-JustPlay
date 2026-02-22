#pragma once
#include <cstddef>
#include <cstdint>

extern "C" {

struct PowGpuCpuHashJob;
PowGpuCpuHashJob* pow_gpu_cpu_hash_create(int device_index, const uint8_t* challenge, size_t challenge_len, uint32_t bits);
void pow_gpu_cpu_hash_destroy(PowGpuCpuHashJob* job);
uint32_t pow_gpu_cpu_hash_batch_size(const PowGpuCpuHashJob* job);
int pow_gpu_cpu_hash_run(PowGpuCpuHashJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16);

struct PowGpuChainJob;
PowGpuChainJob* pow_gpu_chain_create(int device_index, const uint8_t* prefix, size_t prefix_len, uint32_t steps, uint32_t bits);
void pow_gpu_chain_destroy(PowGpuChainJob* job);
uint32_t pow_gpu_chain_batch_size(const PowGpuChainJob* job);
int pow_gpu_chain_run(PowGpuChainJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16);

struct PowGpuBranchyJob;
PowGpuBranchyJob* pow_gpu_branchy_create(int device_index, const uint8_t* prefix, size_t prefix_len, uint32_t rounds, uint32_t bits);
void pow_gpu_branchy_destroy(PowGpuBranchyJob* job);
uint32_t pow_gpu_branchy_batch_size(const PowGpuBranchyJob* job);
int pow_gpu_branchy_run(PowGpuBranchyJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16);

struct PowGpuMemWorkJob;
PowGpuMemWorkJob* pow_gpu_mem_work_create(
    int device_index,
    const uint8_t* init_mem,
    size_t total,
    const uint8_t* acc_prefix,
    size_t acc_prefix_len,
    uint32_t steps,
    uint32_t bits
);
void pow_gpu_mem_work_destroy(PowGpuMemWorkJob* job);
uint32_t pow_gpu_mem_work_batch_size(const PowGpuMemWorkJob* job);
int pow_gpu_mem_work_run(PowGpuMemWorkJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16);

struct PowGpuTinyVmJob;
PowGpuTinyVmJob* pow_gpu_tiny_vm_create(
    int device_index,
    const uint8_t* challenge,
    size_t challenge_len,
    const uint8_t* seed,
    size_t seed_len,
    const uint8_t* program,
    size_t program_len,
    uint32_t steps,
    uint32_t bits
);
void pow_gpu_tiny_vm_destroy(PowGpuTinyVmJob* job);
uint32_t pow_gpu_tiny_vm_batch_size(const PowGpuTinyVmJob* job);
int pow_gpu_tiny_vm_run(PowGpuTinyVmJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16);

}
