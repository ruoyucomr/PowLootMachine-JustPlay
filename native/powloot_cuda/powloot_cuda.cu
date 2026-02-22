#include <cuda_runtime.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "powloot_cuda.h"

#define BLOCK_SIZE 256
#define GRID_SIZE 256
#define DEFAULT_BATCH (BLOCK_SIZE * GRID_SIZE)

static int set_device(int device_index) {
    cudaError_t err = cudaSetDevice(device_index);
    return (err == cudaSuccess) ? 0 : -1;
}

static int copy_to_device(void* dst, const void* src, size_t len) {
    cudaError_t err = cudaMemcpy(dst, src, len, cudaMemcpyHostToDevice);
    return (err == cudaSuccess) ? 0 : -1;
}

static int copy_to_host(void* dst, const void* src, size_t len) {
    cudaError_t err = cudaMemcpy(dst, src, len, cudaMemcpyDeviceToHost);
    return (err == cudaSuccess) ? 0 : -1;
}

__device__ __constant__ unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__device__ __forceinline__ unsigned int rotr(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ void sha256_block(unsigned int state[8], const unsigned char block[64]) {
    unsigned int W[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        W[i] = ((unsigned int)block[i*4] << 24) |
               ((unsigned int)block[i*4+1] << 16) |
               ((unsigned int)block[i*4+2] << 8) |
               (unsigned int)block[i*4+3];
    }
    unsigned int a=state[0],b=state[1],c=state[2],d=state[3];
    unsigned int e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        if (i >= 16) {
            unsigned int s0 = rotr(W[(i+1)&15],7) ^ rotr(W[(i+1)&15],18) ^ (W[(i+1)&15]>>3);
            unsigned int s1 = rotr(W[(i+14)&15],17) ^ rotr(W[(i+14)&15],19) ^ (W[(i+14)&15]>>10);
            W[i&15] = W[i&15] + s0 + W[(i+9)&15] + s1;
        }
        unsigned int S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = h + S1 + ch + K[i] + W[i&15];
        unsigned int S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ __forceinline__ void sha256_block_w(unsigned int state[8], unsigned int W[16]) {
    unsigned int a=state[0],b=state[1],c=state[2],d=state[3];
    unsigned int e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        if (i >= 16) {
            unsigned int s0 = rotr(W[(i+1)&15],7) ^ rotr(W[(i+1)&15],18) ^ (W[(i+1)&15]>>3);
            unsigned int s1 = rotr(W[(i+14)&15],17) ^ rotr(W[(i+14)&15],19) ^ (W[(i+14)&15]>>10);
            W[i&15] = W[i&15] + s0 + W[(i+9)&15] + s1;
        }
        unsigned int S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = h + S1 + ch + K[i] + W[i&15];
        unsigned int S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ __forceinline__ void sha256(const unsigned char* msg, int len, unsigned char* hash) {
    unsigned int state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    // process full blocks
    int i = 0;
    for (; i + 64 <= len; i += 64)
        sha256_block(state, msg + i);
    // final block with padding
    unsigned char last[128];
    int rem = len - i;
    for (int j = 0; j < rem; j++) last[j] = msg[i+j];
    last[rem] = 0x80;
    int pad_len = (rem < 56) ? 64 : 128;
    for (int j = rem+1; j < pad_len; j++) last[j] = 0;
    unsigned long long bitlen = (unsigned long long)len * 8;
    last[pad_len-8] = (bitlen >> 56) & 0xff;
    last[pad_len-7] = (bitlen >> 48) & 0xff;
    last[pad_len-6] = (bitlen >> 40) & 0xff;
    last[pad_len-5] = (bitlen >> 32) & 0xff;
    last[pad_len-4] = (bitlen >> 24) & 0xff;
    last[pad_len-3] = (bitlen >> 16) & 0xff;
    last[pad_len-2] = (bitlen >> 8) & 0xff;
    last[pad_len-1] = bitlen & 0xff;
    for (int j = 0; j < pad_len; j += 64)
        sha256_block(state, last + j);
    for (int j = 0; j < 8; j++) {
        hash[j*4]   = (state[j] >> 24) & 0xff;
        hash[j*4+1] = (state[j] >> 16) & 0xff;
        hash[j*4+2] = (state[j] >> 8) & 0xff;
        hash[j*4+3] = state[j] & 0xff;
    }
}

__device__ __forceinline__ int leading_zero_bits(const unsigned char* h) {
    for (int i = 0; i < 8; i++) {
        unsigned int w = ((unsigned int)h[i*4] << 24) | ((unsigned int)h[i*4+1] << 16) |
                         ((unsigned int)h[i*4+2] << 8) | (unsigned int)h[i*4+3];
        if (w) return i * 32 + __clz(w);
    }
    return 256;
}

__device__ const char HEX_CHARS[] = "0123456789abcdef";

__device__ void bytes_to_hex(const unsigned char* src, int len, char* dst) {
    for (int i = 0; i < len; i++) {
        dst[i*2]   = HEX_CHARS[(src[i] >> 4) & 0xf];
        dst[i*2+1] = HEX_CHARS[src[i] & 0xf];
    }
}

// ---------- CPU_HASH kernel ----------
// Each thread: nonce = prefix(12B) || thread_idx(4B) -> hex -> sha256(challenge + nonce_hex)
extern "C" __global__ void mine_cpu_hash(
    const unsigned char* challenge, int challenge_len,
    const unsigned char* nonce_prefix,
    int target_bits, unsigned int batch_offset,
    int* found_flag, unsigned char* result_nonce
) {
    if (*found_flag) return;
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x + batch_offset;

    // build 16-byte nonce
    unsigned char nonce_bytes[16];
    for (int i = 0; i < 12; i++) nonce_bytes[i] = nonce_prefix[i];
    nonce_bytes[12] = (tid >> 24) & 0xff;
    nonce_bytes[13] = (tid >> 16) & 0xff;
    nonce_bytes[14] = (tid >> 8) & 0xff;
    nonce_bytes[15] = tid & 0xff;

    // to hex (32 chars)
    char nonce_hex[32];
    bytes_to_hex(nonce_bytes, 16, nonce_hex);

    // build message: challenge + nonce_hex
    unsigned char msg[512];
    int msg_len = challenge_len + 32;
    for (int i = 0; i < challenge_len; i++) msg[i] = challenge[i];
    for (int i = 0; i < 32; i++) msg[challenge_len + i] = (unsigned char)nonce_hex[i];

    unsigned char hash[32];
    sha256(msg, msg_len, hash);

    if (leading_zero_bits(hash) >= target_bits) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for (int i = 0; i < 16; i++) result_nonce[i] = nonce_bytes[i];
        }
    }
}

// ---------- CHAIN kernel ----------
// sha256( challenge_utf8 || seed_bytes || nonce_hex ) then iterate `steps` times
extern "C" __global__ void mine_chain(
    const unsigned char* prefix, int prefix_len,
    int steps, int target_bits, unsigned int batch_offset,
    const unsigned char* nonce_prefix,
    int* found_flag, unsigned char* result_nonce
) {
    if (*found_flag) return;
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x + batch_offset;

    unsigned char nonce_bytes[16];
    for (int i = 0; i < 12; i++) nonce_bytes[i] = nonce_prefix[i];
    nonce_bytes[12] = (tid >> 24) & 0xff;
    nonce_bytes[13] = (tid >> 16) & 0xff;
    nonce_bytes[14] = (tid >> 8) & 0xff;
    nonce_bytes[15] = tid & 0xff;

    char nonce_hex[32];
    bytes_to_hex(nonce_bytes, 16, nonce_hex);

    // initial buffer: prefix(challenge+seed) + nonce_hex
    unsigned char buf[512];
    int buf_len = prefix_len + 32;
    for (int i = 0; i < prefix_len; i++) buf[i] = prefix[i];
    for (int i = 0; i < 32; i++) buf[prefix_len + i] = (unsigned char)nonce_hex[i];

    unsigned char hash[32];
    sha256(buf, buf_len, hash);

    // chain: hash = sha256(hash) for steps-1 more times
    for (int s = 1; s < steps; s++) {
        unsigned char tmp[32];
        sha256(hash, 32, tmp);
        for (int i = 0; i < 32; i++) hash[i] = tmp[i];
    }

    if (leading_zero_bits(hash) >= target_bits) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for (int i = 0; i < 16; i++) result_nonce[i] = nonce_bytes[i];
        }
    }
}

// ---------- helper functions for branchy/vm/mem kernels ----------
__device__ unsigned int rotl32(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

__device__ unsigned int read_le32(const unsigned char* p) {
    return (unsigned int)p[0] | ((unsigned int)p[1]<<8) |
           ((unsigned int)p[2]<<16) | ((unsigned int)p[3]<<24);
}

__device__ void write_le32(unsigned char* p, unsigned int v) {
    p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff;
}

// Fast SHA-256 for MEM_WORK step: hash(acc[32] + slice[sl_len] + le32(step))
// Common path: sl_len=32 -> 68 bytes = exactly 2 SHA-256 blocks
// Constructs W[] directly from input bytes - no intermediate blk[64] array
__device__ __forceinline__ void sha256_mem_step(
    const unsigned char* acc, const unsigned char* slice, int sl_len,
    unsigned int step, unsigned char* out
) {
    unsigned int state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    if (sl_len == 32) {
        // Block 1: W[0..7] from acc, W[8..15] from slice
        unsigned int W[16];
        #pragma unroll
        for (int i = 0; i < 8; i++)
            W[i] = ((unsigned int)acc[i*4]<<24)|((unsigned int)acc[i*4+1]<<16)|((unsigned int)acc[i*4+2]<<8)|(unsigned int)acc[i*4+3];
        #pragma unroll
        for (int i = 0; i < 8; i++)
            W[8+i] = ((unsigned int)slice[i*4]<<24)|((unsigned int)slice[i*4+1]<<16)|((unsigned int)slice[i*4+2]<<8)|(unsigned int)slice[i*4+3];
        sha256_block_w(state, W);
        // Block 2: le32(step) + 0x80 + zeros + be64(544)
        W[0] = ((step&0xff)<<24)|((step>>8&0xff)<<16)|((step>>16&0xff)<<8)|(step>>24);
        W[1] = 0x80000000u;
        #pragma unroll
        for (int i = 2; i < 15; i++) W[i] = 0;
        W[15] = 0x00000220u;
        sha256_block_w(state, W);
    } else {
        unsigned char buf[68];
        for (int i = 0; i < 32; i++) buf[i] = acc[i];
        for (int i = 0; i < sl_len; i++) buf[32+i] = slice[i];
        buf[32+sl_len]=step; buf[33+sl_len]=step>>8;
        buf[34+sl_len]=step>>16; buf[35+sl_len]=step>>24;
        sha256(buf, 32+sl_len+4, out); return;
    }
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i*4]=(state[i]>>24); out[i*4+1]=(state[i]>>16);
        out[i*4+2]=(state[i]>>8); out[i*4+3]=state[i];
    }
}

// ---------- MEM_WORK kernel ----------
extern "C" __global__ __launch_bounds__(256, 3) void mine_mem_work(
    const unsigned char* init_mem,
    unsigned char* work_mem,
    int total, int mask,
    const unsigned char* acc_prefix, int acc_prefix_len,
    const unsigned char* nonce_prefix,
    int steps, int target_bits, int iters,
    int* found_flag, unsigned char* result_nonce
) {
    if (*found_flag) return;
    unsigned int local_id = blockIdx.x * blockDim.x + threadIdx.x;

    // each thread owns a fixed work_mem slot
    unsigned char* mc = work_mem + (unsigned long long)local_id * total;
    const int n4 = total >> 4;

    for (int it = 0; it < iters; it++) {
        if (*found_flag) return;
        unsigned int nonce_id = local_id * iters + it;

        // build nonce
        unsigned char nonce_bytes[16];
        for (int i = 0; i < 12; i++) nonce_bytes[i] = nonce_prefix[i];
        nonce_bytes[12] = (nonce_id >> 24) & 0xff;
        nonce_bytes[13] = (nonce_id >> 16) & 0xff;
        nonce_bytes[14] = (nonce_id >> 8) & 0xff;
        nonce_bytes[15] = nonce_id & 0xff;

        char nonce_hex[32];
        bytes_to_hex(nonce_bytes, 16, nonce_hex);

        // re-copy init memory (stays warm in cache across iterations)
        {
            uint4* dst4 = (uint4*)mc;
            const uint4* src4 = (const uint4*)init_mem;
            for (int i = 0; i < n4; i++) dst4[i] = src4[i];
        }

        // acc = sha256(acc_prefix + nonce_hex)
        unsigned char msg[128];
        int msg_len = acc_prefix_len + 32;
        for (int i = 0; i < acc_prefix_len; i++) msg[i] = acc_prefix[i];
        for (int i = 0; i < 32; i++) msg[acc_prefix_len + i] = (unsigned char)nonce_hex[i];

        unsigned char acc[32];
        sha256(msg, msg_len, acc);

        unsigned int idx = read_le32(acc) & mask;

        for (int i = 0; i < steps; i++) {
            int sl_len = (idx + 32 <= total) ? 32 : (total - idx);
            sha256_mem_step(acc, mc + idx, sl_len, (unsigned int)i, acc);
            for (int j = 0; j < sl_len; j++) mc[idx+j] ^= acc[j];
            idx = (idx + 1 + read_le32(acc)) & mask;
        }

        if (leading_zero_bits(acc) >= target_bits) {
            if (atomicCAS(found_flag, 0, 1) == 0) {
                for (int i = 0; i < 16; i++) result_nonce[i] = nonce_bytes[i];
            }
            return;
        }
    }
}

// ---------- BRANCHY_MIX kernel ----------
extern "C" __global__ void mine_branchy_mix(
    const unsigned char* prefix, int prefix_len,
    const unsigned char* nonce_prefix,
    int rounds, int target_bits,
    int* found_flag, unsigned char* result_nonce
) {
    if (*found_flag) return;
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;

    unsigned char nonce_bytes[16];
    for (int i = 0; i < 12; i++) nonce_bytes[i] = nonce_prefix[i];
    nonce_bytes[12] = (tid >> 24) & 0xff;
    nonce_bytes[13] = (tid >> 16) & 0xff;
    nonce_bytes[14] = (tid >> 8) & 0xff;
    nonce_bytes[15] = tid & 0xff;
    char nonce_hex[32];
    bytes_to_hex(nonce_bytes, 16, nonce_hex);

    // sha256(prefix + nonce_hex) -> d[32]
    unsigned char msg[512];
    int msg_len = prefix_len + 32;
    for (int i = 0; i < prefix_len; i++) msg[i] = prefix[i];
    for (int i = 0; i < 32; i++) msg[prefix_len + i] = (unsigned char)nonce_hex[i];
    unsigned char d[32];
    sha256(msg, msg_len, d);

    unsigned int a=read_le32(d), b=read_le32(d+4), c=read_le32(d+8), dd=read_le32(d+12);
    unsigned int t0=read_le32(d+16), t1=read_le32(d+20), t2=read_le32(d+24), t3=read_le32(d+28);

    unsigned int T[16];
    for (int i = 0; i < 16; i++) {
        t0 ^= (t0 << 13); t0 ^= (t0 >> 17); t0 ^= (t0 << 5);
        t1 += 0x9e3779b9u + (t0 ^ (unsigned int)i);
        t2 = rotl32(t2 ^ t1, (i % 31) + 1);
        t3 ^= (t2 + 0x7f4a7c15u);
        T[i] = t0 ^ t1 ^ t2 ^ t3;
    }

    for (int i = 0; i < rounds; i++) {
        unsigned int s = a ^ rotl32(b, 7) ^ (c * 0x9e3779b9u) ^ (unsigned int)i;
        unsigned int sel = s & 3;
        if (sel == 0) {
            a += rotl32(dd, 11); b ^= rotl32(a, 3);
            c += (b ^ 0x85ebca6bu); dd ^= rotl32(c, 17);
        } else if (sel == 1) {
            a = ((a ^ 0x27d4eb2du) * (b | 1)) + c;
            b = ((b ^ 0x165667b1u) * (c | 1)) + dd;
            c = ((c ^ 0xd3a2646cu) * (dd | 1)) + a;
            dd = ((dd ^ 0xfd7046c5u) * (a | 1)) + b;
        } else if (sel == 2) {
            unsigned int idx = (rotl32(s, 5) ^ (b >> 3)) & 15;
            unsigned int v = T[idx];
            a ^= v; b += rotl32(v, (a & 15) + 1);
            c ^= (v + (unsigned int)i); dd += (a ^ c);
        } else {
            unsigned int idx = (s ^ rotl32(a, 9)) & 15;
            unsigned int v = T[idx] ^ rotl32(T[(idx + 7) & 15], 13);
            a = rotl32(a ^ v, 9) + b; b = rotl32(b + v, 5) ^ c;
            c = rotl32(c ^ (a + (unsigned int)i), 3) + dd;
            dd = rotl32(dd + (b ^ (unsigned int)i), 7) ^ a;
        }
        unsigned int tmp = a;
        a += c; c ^= b; b += dd; dd ^= tmp;
    }

    // pack 16 bytes, sha256, check bits
    unsigned char out16[16];
    write_le32(out16, a); write_le32(out16+4, b);
    write_le32(out16+8, c); write_le32(out16+12, dd);
    unsigned char hash[32];
    sha256(out16, 16, hash);

    if (leading_zero_bits(hash) >= target_bits) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for (int i = 0; i < 16; i++) result_nonce[i] = nonce_bytes[i];
        }
    }
}

// ---------- TINY_VM kernel ----------
extern "C" __global__ void mine_tiny_vm(
    const unsigned char* challenge, int challenge_len,
    const unsigned char* seed, int seed_len,
    const unsigned char* nonce_prefix,
    const unsigned char* program, int prog_ins,
    int vm_steps, int target_bits,
    unsigned int* work_mem,
    int* found_flag, unsigned char* result_nonce
) {
    if (*found_flag) return;
    unsigned int local_id = blockIdx.x * blockDim.x + threadIdx.x;

    unsigned char nonce_bytes[16];
    for (int i = 0; i < 12; i++) nonce_bytes[i] = nonce_prefix[i];
    nonce_bytes[12] = (local_id >> 24) & 0xff;
    nonce_bytes[13] = (local_id >> 16) & 0xff;
    nonce_bytes[14] = (local_id >> 8) & 0xff;
    nonce_bytes[15] = local_id & 0xff;
    char nonce_hex[32];
    bytes_to_hex(nonce_bytes, 16, nonce_hex);

    // init = sha256("challenge|seed|nonce_hex")
    unsigned char buf[512];
    int blen = 0;
    for (int i = 0; i < challenge_len; i++) buf[blen++] = challenge[i];
    buf[blen++] = '|';
    for (int i = 0; i < seed_len; i++) buf[blen++] = seed[i];
    buf[blen++] = '|';
    for (int i = 0; i < 32; i++) buf[blen++] = (unsigned char)nonce_hex[i];
    unsigned char init[32];
    sha256(buf, blen, init);

    // derive regs[16]
    unsigned int regs[16];
    for (int i = 0; i < 16; i++) {
        unsigned int u = read_le32(init + ((i * 4) % 32));
        regs[i] = u ^ (0x9e3779b9u * (unsigned int)(i + 1));
    }

    // derive mem[1024] in global memory
    unsigned int* mem = work_mem + (unsigned long long)local_id * 1024;
    unsigned char st[32];
    // st = sha256("mem:" + init)
    unsigned char mb[36];
    mb[0]='m'; mb[1]='e'; mb[2]='m'; mb[3]=':';
    for (int i = 0; i < 32; i++) mb[4+i] = init[i];
    sha256(mb, 36, st);

    for (int i = 0; i < 1024; i++) {
        if ((i & 7) == 0) { unsigned char tmp[32]; sha256(st, 32, tmp); for(int j=0;j<32;j++) st[j]=tmp[j]; }
        mem[i] = read_le32(st + ((i & 7) * 4));
    }

    // run VM
    int pc = 0;
    for (int fuel = 0; fuel < vm_steps; fuel++) {
        if (pc < 0 || pc >= prog_ins) goto done;
        int off4 = pc * 4;
        unsigned char op = program[off4];
        unsigned char ab = program[off4+1];
        unsigned char bb = program[off4+2];
        unsigned char imm = program[off4+3];
        int a = ab & 15, b = bb & 15, target = bb;

        if (op == 0) { regs[a] = regs[a] + regs[b] + imm; pc++; }
        else if (op == 1) { regs[a] = regs[a] ^ regs[b] ^ imm; pc++; }
        else if (op == 2) { regs[a] = (regs[a] ^ imm) * (regs[b] | 1); pc++; }
        else if (op == 3) { regs[a] = rotl32(regs[a] ^ regs[b], imm & 31); pc++; }
        else if (op == 4) { regs[a] = mem[(regs[b] + imm) & 1023]; pc++; }
        else if (op == 5) { mem[(regs[b] + imm) & 1023] = regs[a]; pc++; }
        else if (op == 6) { regs[a] = ((regs[b] & (1u << (imm & 31))) != 0) ? 1 : 0; pc++; }
        else if (op == 7) { pc = (regs[a] & (1u << (imm & 31))) ? target : pc + 1; }
        else if (op == 8) { pc = target; }
        else if (op == 9) { break; }
        else goto done;
    }

    {
        // digest: hash regs + sparse mem sample
        unsigned char dbuf[192]; // (16+32)*4 = 192
        int doff = 0;
        for (int i = 0; i < 16; i++) { write_le32(dbuf+doff, regs[i]); doff += 4; }
        int stride = 1024 / 32; // = 32
        for (int i = 0; i < 32; i++) { write_le32(dbuf+doff, mem[(i*stride)&1023]); doff += 4; }
        unsigned char hash[32];
        sha256(dbuf, 192, hash);

        if (leading_zero_bits(hash) >= target_bits) {
            if (atomicCAS(found_flag, 0, 1) == 0) {
                for (int i = 0; i < 16; i++) result_nonce[i] = nonce_bytes[i];
            }
        }
    }
    done:;
}

struct PowGpuCpuHashJob {
    int device;
    int challenge_len;
    uint32_t target_bits;
    uint8_t* d_challenge;
    uint8_t* d_nonce_prefix;
    int* d_found;
    uint8_t* d_result;
    uint32_t batch_size;
};

struct PowGpuChainJob {
    int device;
    int prefix_len;
    int steps;
    int bits;
    uint8_t* d_prefix;
    uint8_t* d_nonce_prefix;
    int* d_found;
    uint8_t* d_result;
    uint32_t batch_size;
};

struct PowGpuBranchyJob {
    int device;
    int prefix_len;
    int rounds;
    int bits;
    uint8_t* d_prefix;
    uint8_t* d_nonce_prefix;
    int* d_found;
    uint8_t* d_result;
    uint32_t batch_size;
};

struct PowGpuMemWorkJob {
    int device;
    int total;
    int mask;
    int steps;
    int bits;
    int iters;
    int grid;
    uint32_t threads;
    uint32_t batch_size;
    uint8_t* d_init;
    uint8_t* d_work;
    uint8_t* d_acc_prefix;
    int acc_prefix_len;
    uint8_t* d_nonce_prefix;
    int* d_found;
    uint8_t* d_result;
};

struct PowGpuTinyVmJob {
    int device;
    int challenge_len;
    int seed_len;
    int prog_ins;
    int steps;
    int bits;
    int grid;
    uint32_t threads;
    uint32_t batch_size;
    uint8_t* d_challenge;
    uint8_t* d_seed;
    uint8_t* d_program;
    uint8_t* d_nonce_prefix;
    uint32_t* d_work;
    int* d_found;
    uint8_t* d_result;
};

static void free_dev(void* ptr) {
    if (ptr) cudaFree(ptr);
}

extern "C" PowGpuCpuHashJob* pow_gpu_cpu_hash_create(int device_index, const uint8_t* challenge, size_t challenge_len, uint32_t bits) {
    if (!challenge || challenge_len == 0) return nullptr;
    if (set_device(device_index) != 0) return nullptr;

    PowGpuCpuHashJob* job = (PowGpuCpuHashJob*)malloc(sizeof(PowGpuCpuHashJob));
    if (!job) return nullptr;
    memset(job, 0, sizeof(PowGpuCpuHashJob));
    job->device = device_index;
    job->challenge_len = (int)challenge_len;
    job->target_bits = bits;
    job->batch_size = DEFAULT_BATCH;

    if (cudaMalloc(&job->d_challenge, challenge_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_challenge, challenge, challenge_len) != 0) goto fail;
    if (cudaMalloc(&job->d_nonce_prefix, 12) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_found, sizeof(int)) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_result, 16) != cudaSuccess) goto fail;
    return job;

fail:
    if (job) {
        free_dev(job->d_challenge);
        free_dev(job->d_nonce_prefix);
        free_dev(job->d_found);
        free_dev(job->d_result);
        free(job);
    }
    return nullptr;
}

extern "C" void pow_gpu_cpu_hash_destroy(PowGpuCpuHashJob* job) {
    if (!job) return;
    set_device(job->device);
    free_dev(job->d_challenge);
    free_dev(job->d_nonce_prefix);
    free_dev(job->d_found);
    free_dev(job->d_result);
    free(job);
}

extern "C" uint32_t pow_gpu_cpu_hash_batch_size(const PowGpuCpuHashJob* job) {
    return job ? job->batch_size : 0;
}

extern "C" int pow_gpu_cpu_hash_run(PowGpuCpuHashJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16) {
    if (!job || !nonce_prefix12 || !out_nonce16) return -1;
    if (set_device(job->device) != 0) return -2;
    if (copy_to_device(job->d_nonce_prefix, nonce_prefix12, 12) != 0) return -3;
    cudaMemset(job->d_found, 0, sizeof(int));

    mine_cpu_hash<<<GRID_SIZE, BLOCK_SIZE>>>(job->d_challenge, job->challenge_len,
                                             job->d_nonce_prefix, (int)job->target_bits, 0,
                                             job->d_found, job->d_result);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return -4;
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -5;

    int found = 0;
    if (copy_to_host(&found, job->d_found, sizeof(int)) != 0) return -6;
    if (found) {
        if (copy_to_host(out_nonce16, job->d_result, 16) != 0) return -7;
        return 1;
    }
    return 0;
}

extern "C" PowGpuChainJob* pow_gpu_chain_create(int device_index, const uint8_t* prefix, size_t prefix_len, uint32_t steps, uint32_t bits) {
    if (!prefix || prefix_len == 0) return nullptr;
    if (set_device(device_index) != 0) return nullptr;

    PowGpuChainJob* job = (PowGpuChainJob*)malloc(sizeof(PowGpuChainJob));
    if (!job) return nullptr;
    memset(job, 0, sizeof(PowGpuChainJob));
    job->device = device_index;
    job->prefix_len = (int)prefix_len;
    job->steps = (int)steps;
    job->bits = (int)bits;
    job->batch_size = DEFAULT_BATCH;

    if (cudaMalloc(&job->d_prefix, prefix_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_prefix, prefix, prefix_len) != 0) goto fail;
    if (cudaMalloc(&job->d_nonce_prefix, 12) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_found, sizeof(int)) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_result, 16) != cudaSuccess) goto fail;
    return job;

fail:
    if (job) {
        free_dev(job->d_prefix);
        free_dev(job->d_nonce_prefix);
        free_dev(job->d_found);
        free_dev(job->d_result);
        free(job);
    }
    return nullptr;
}

extern "C" void pow_gpu_chain_destroy(PowGpuChainJob* job) {
    if (!job) return;
    set_device(job->device);
    free_dev(job->d_prefix);
    free_dev(job->d_nonce_prefix);
    free_dev(job->d_found);
    free_dev(job->d_result);
    free(job);
}

extern "C" uint32_t pow_gpu_chain_batch_size(const PowGpuChainJob* job) {
    return job ? job->batch_size : 0;
}

extern "C" int pow_gpu_chain_run(PowGpuChainJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16) {
    if (!job || !nonce_prefix12 || !out_nonce16) return -1;
    if (set_device(job->device) != 0) return -2;
    if (copy_to_device(job->d_nonce_prefix, nonce_prefix12, 12) != 0) return -3;
    cudaMemset(job->d_found, 0, sizeof(int));

    mine_chain<<<GRID_SIZE, BLOCK_SIZE>>>(job->d_prefix, job->prefix_len, job->steps, job->bits, 0,
                                          job->d_nonce_prefix, job->d_found, job->d_result);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return -4;
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -5;

    int found = 0;
    if (copy_to_host(&found, job->d_found, sizeof(int)) != 0) return -6;
    if (found) {
        if (copy_to_host(out_nonce16, job->d_result, 16) != 0) return -7;
        return 1;
    }
    return 0;
}

extern "C" PowGpuBranchyJob* pow_gpu_branchy_create(int device_index, const uint8_t* prefix, size_t prefix_len, uint32_t rounds, uint32_t bits) {
    if (!prefix || prefix_len == 0) return nullptr;
    if (set_device(device_index) != 0) return nullptr;

    PowGpuBranchyJob* job = (PowGpuBranchyJob*)malloc(sizeof(PowGpuBranchyJob));
    if (!job) return nullptr;
    memset(job, 0, sizeof(PowGpuBranchyJob));
    job->device = device_index;
    job->prefix_len = (int)prefix_len;
    job->rounds = (int)rounds;
    job->bits = (int)bits;
    job->batch_size = DEFAULT_BATCH;

    if (cudaMalloc(&job->d_prefix, prefix_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_prefix, prefix, prefix_len) != 0) goto fail;
    if (cudaMalloc(&job->d_nonce_prefix, 12) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_found, sizeof(int)) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_result, 16) != cudaSuccess) goto fail;
    return job;

fail:
    if (job) {
        free_dev(job->d_prefix);
        free_dev(job->d_nonce_prefix);
        free_dev(job->d_found);
        free_dev(job->d_result);
        free(job);
    }
    return nullptr;
}

extern "C" void pow_gpu_branchy_destroy(PowGpuBranchyJob* job) {
    if (!job) return;
    set_device(job->device);
    free_dev(job->d_prefix);
    free_dev(job->d_nonce_prefix);
    free_dev(job->d_found);
    free_dev(job->d_result);
    free(job);
}

extern "C" uint32_t pow_gpu_branchy_batch_size(const PowGpuBranchyJob* job) {
    return job ? job->batch_size : 0;
}

extern "C" int pow_gpu_branchy_run(PowGpuBranchyJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16) {
    if (!job || !nonce_prefix12 || !out_nonce16) return -1;
    if (set_device(job->device) != 0) return -2;
    if (copy_to_device(job->d_nonce_prefix, nonce_prefix12, 12) != 0) return -3;
    cudaMemset(job->d_found, 0, sizeof(int));

    mine_branchy_mix<<<GRID_SIZE, BLOCK_SIZE>>>(job->d_prefix, job->prefix_len, job->d_nonce_prefix,
                                                job->rounds, job->bits, job->d_found, job->d_result);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return -4;
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -5;

    int found = 0;
    if (copy_to_host(&found, job->d_found, sizeof(int)) != 0) return -6;
    if (found) {
        if (copy_to_host(out_nonce16, job->d_result, 16) != 0) return -7;
        return 1;
    }
    return 0;
}

extern "C" PowGpuMemWorkJob* pow_gpu_mem_work_create(
    int device_index,
    const uint8_t* init_mem,
    size_t total,
    const uint8_t* acc_prefix,
    size_t acc_prefix_len,
    uint32_t steps,
    uint32_t bits
) {
    if (!init_mem || total == 0 || !acc_prefix || acc_prefix_len == 0) return nullptr;
    if (total > 0x7fffffff) return nullptr;
    if (acc_prefix_len > 0x7fffffff) return nullptr;
    if (set_device(device_index) != 0) return nullptr;

    PowGpuMemWorkJob* job = (PowGpuMemWorkJob*)malloc(sizeof(PowGpuMemWorkJob));
    if (!job) return nullptr;
    memset(job, 0, sizeof(PowGpuMemWorkJob));
    job->device = device_index;
    job->total = (int)total;
    job->mask = (int)(total - 1);
    job->steps = (int)steps;
    job->bits = (int)bits;
    job->acc_prefix_len = (int)acc_prefix_len;

    if (cudaMalloc(&job->d_init, total) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_init, init_mem, total) != 0) goto fail;
    if (cudaMalloc(&job->d_acc_prefix, acc_prefix_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_acc_prefix, acc_prefix, acc_prefix_len) != 0) goto fail;
    if (cudaMalloc(&job->d_nonce_prefix, 12) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_found, sizeof(int)) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_result, 16) != cudaSuccess) goto fail;

    size_t free_mem = 0;
    size_t total_mem = 0;
    if (cudaMemGetInfo(&free_mem, &total_mem) != cudaSuccess) goto fail;
    size_t mem_limit = (size_t)(free_mem * 0.8) / total;
    size_t threads = mem_limit;
    if (threads > 2048) threads = 2048;
    threads = (threads / BLOCK_SIZE) * BLOCK_SIZE;
    if (threads < BLOCK_SIZE) threads = BLOCK_SIZE;
    size_t iters = DEFAULT_BATCH / threads;
    if (iters < 1) iters = 1;

    while (threads >= BLOCK_SIZE) {
        size_t work_size = threads * total;
        if (threads != 0 && work_size / threads != total) goto fail;
        if (cudaMalloc(&job->d_work, work_size) == cudaSuccess) {
            job->threads = (uint32_t)threads;
            job->iters = (int)iters;
            job->grid = (int)(threads / BLOCK_SIZE);
            job->batch_size = (uint32_t)(threads * iters);
            break;
        }
        threads -= BLOCK_SIZE;
        if (threads < BLOCK_SIZE) break;
        iters = DEFAULT_BATCH / threads;
        if (iters < 1) iters = 1;
    }

    if (!job->d_work) goto fail;
    return job;

fail:
    if (job) {
        free_dev(job->d_init);
        free_dev(job->d_work);
        free_dev(job->d_acc_prefix);
        free_dev(job->d_nonce_prefix);
        free_dev(job->d_found);
        free_dev(job->d_result);
        free(job);
    }
    return nullptr;
}

extern "C" void pow_gpu_mem_work_destroy(PowGpuMemWorkJob* job) {
    if (!job) return;
    set_device(job->device);
    free_dev(job->d_init);
    free_dev(job->d_work);
    free_dev(job->d_acc_prefix);
    free_dev(job->d_nonce_prefix);
    free_dev(job->d_found);
    free_dev(job->d_result);
    free(job);
}

extern "C" uint32_t pow_gpu_mem_work_batch_size(const PowGpuMemWorkJob* job) {
    return job ? job->batch_size : 0;
}

extern "C" int pow_gpu_mem_work_run(PowGpuMemWorkJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16) {
    if (!job || !nonce_prefix12 || !out_nonce16) return -1;
    if (set_device(job->device) != 0) return -2;
    if (copy_to_device(job->d_nonce_prefix, nonce_prefix12, 12) != 0) return -3;
    cudaMemset(job->d_found, 0, sizeof(int));

    dim3 block(BLOCK_SIZE, 1, 1);
    dim3 grid(job->grid, 1, 1);
    mine_mem_work<<<grid, block>>>(
        job->d_init,
        job->d_work,
        job->total, job->mask,
        job->d_acc_prefix, job->acc_prefix_len,
        job->d_nonce_prefix,
        job->steps, job->bits, job->iters,
        job->d_found, job->d_result
    );
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return -4;
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -5;

    int found = 0;
    if (copy_to_host(&found, job->d_found, sizeof(int)) != 0) return -6;
    if (found) {
        if (copy_to_host(out_nonce16, job->d_result, 16) != 0) return -7;
        return 1;
    }
    return 0;
}

extern "C" PowGpuTinyVmJob* pow_gpu_tiny_vm_create(
    int device_index,
    const uint8_t* challenge,
    size_t challenge_len,
    const uint8_t* seed,
    size_t seed_len,
    const uint8_t* program,
    size_t program_len,
    uint32_t steps,
    uint32_t bits
) {
    if (!challenge || challenge_len == 0 || !seed || seed_len == 0 || !program || program_len == 0) return nullptr;
    if (program_len % 4 != 0) return nullptr;
    if (challenge_len > 0x7fffffff || seed_len > 0x7fffffff || program_len > 0x7fffffff) return nullptr;
    if (set_device(device_index) != 0) return nullptr;

    PowGpuTinyVmJob* job = (PowGpuTinyVmJob*)malloc(sizeof(PowGpuTinyVmJob));
    if (!job) return nullptr;
    memset(job, 0, sizeof(PowGpuTinyVmJob));
    job->device = device_index;
    job->challenge_len = (int)challenge_len;
    job->seed_len = (int)seed_len;
    job->prog_ins = (int)(program_len / 4);
    job->steps = (int)steps;
    job->bits = (int)bits;

    if (cudaMalloc(&job->d_challenge, challenge_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_challenge, challenge, challenge_len) != 0) goto fail;
    if (cudaMalloc(&job->d_seed, seed_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_seed, seed, seed_len) != 0) goto fail;
    if (cudaMalloc(&job->d_program, program_len) != cudaSuccess) goto fail;
    if (copy_to_device(job->d_program, program, program_len) != 0) goto fail;
    if (cudaMalloc(&job->d_nonce_prefix, 12) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_found, sizeof(int)) != cudaSuccess) goto fail;
    if (cudaMalloc(&job->d_result, 16) != cudaSuccess) goto fail;

    size_t free_mem = 0;
    size_t total_mem = 0;
    if (cudaMemGetInfo(&free_mem, &total_mem) != cudaSuccess) goto fail;
    size_t per_thread = 1024 * sizeof(uint32_t);
    size_t max_threads = (size_t)(free_mem * 0.8) / per_thread;
    if (max_threads > DEFAULT_BATCH) max_threads = DEFAULT_BATCH;
    max_threads = (max_threads / BLOCK_SIZE) * BLOCK_SIZE;
    if (max_threads < BLOCK_SIZE) max_threads = BLOCK_SIZE;

    size_t threads = max_threads;
    while (threads >= BLOCK_SIZE) {
        size_t work_size = threads * per_thread;
        if (threads != 0 && work_size / threads != per_thread) goto fail;
        if (cudaMalloc(&job->d_work, work_size) == cudaSuccess) {
            job->threads = (uint32_t)threads;
            job->grid = (int)(threads / BLOCK_SIZE);
            job->batch_size = (uint32_t)threads;
            break;
        }
        threads -= BLOCK_SIZE;
        if (threads < BLOCK_SIZE) break;
    }

    if (!job->d_work) goto fail;
    return job;

fail:
    if (job) {
        free_dev(job->d_challenge);
        free_dev(job->d_seed);
        free_dev(job->d_program);
        free_dev(job->d_nonce_prefix);
        free_dev(job->d_work);
        free_dev(job->d_found);
        free_dev(job->d_result);
        free(job);
    }
    return nullptr;
}

extern "C" void pow_gpu_tiny_vm_destroy(PowGpuTinyVmJob* job) {
    if (!job) return;
    set_device(job->device);
    free_dev(job->d_challenge);
    free_dev(job->d_seed);
    free_dev(job->d_program);
    free_dev(job->d_nonce_prefix);
    free_dev(job->d_work);
    free_dev(job->d_found);
    free_dev(job->d_result);
    free(job);
}

extern "C" uint32_t pow_gpu_tiny_vm_batch_size(const PowGpuTinyVmJob* job) {
    return job ? job->batch_size : 0;
}

extern "C" int pow_gpu_tiny_vm_run(PowGpuTinyVmJob* job, const uint8_t* nonce_prefix12, uint8_t* out_nonce16) {
    if (!job || !nonce_prefix12 || !out_nonce16) return -1;
    if (set_device(job->device) != 0) return -2;
    if (copy_to_device(job->d_nonce_prefix, nonce_prefix12, 12) != 0) return -3;
    cudaMemset(job->d_found, 0, sizeof(int));

    dim3 block(BLOCK_SIZE, 1, 1);
    dim3 grid(job->grid, 1, 1);
    mine_tiny_vm<<<grid, block>>>(
        job->d_challenge, job->challenge_len,
        job->d_seed, job->seed_len,
        job->d_nonce_prefix,
        job->d_program, job->prog_ins,
        job->steps, job->bits,
        job->d_work,
        job->d_found, job->d_result
    );
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return -4;
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -5;

    int found = 0;
    if (copy_to_host(&found, job->d_found, sizeof(int)) != 0) return -6;
    if (found) {
        if (copy_to_host(out_nonce16, job->d_result, 16) != 0) return -7;
        return 1;
    }
    return 0;
}

