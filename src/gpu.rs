use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;

#[repr(C)]
struct Argon2GpuJob {
    _private: [u8; 0],
}

#[repr(C)]
struct PowGpuCpuHashJob {
    _private: [u8; 0],
}

#[repr(C)]
struct PowGpuChainJob {
    _private: [u8; 0],
}

#[repr(C)]
struct PowGpuBranchyJob {
    _private: [u8; 0],
}

#[repr(C)]
struct PowGpuMemWorkJob {
    _private: [u8; 0],
}

#[repr(C)]
struct PowGpuTinyVmJob {
    _private: [u8; 0],
}

#[link(name = "argon2_cuda_wrapper", kind = "static")]
unsafe extern "C" {
    fn argon2_gpu_device_count() -> c_int;
    fn argon2_gpu_device_name(index: c_int, out: *mut c_char, out_len: usize) -> c_int;

    fn argon2_gpu_job_create(
        device_index: c_int,
        salt: *const u8,
        salt_len: usize,
        m_cost: u32,
        t_cost: u32,
        lanes: u32,
        jobs_per_block: u32,
        batch_size: usize,
    ) -> *mut Argon2GpuJob;

    fn argon2_gpu_job_destroy(job: *mut Argon2GpuJob);
    fn argon2_gpu_job_batch_size(job: *const Argon2GpuJob) -> usize;

    fn argon2_gpu_hash_batch(
        job: *mut Argon2GpuJob,
        pw_base: *const u8,
        pw_stride: usize,
        pw_lens: *const u32,
        batch: usize,
        out_hashes: *mut u8,
    ) -> c_int;
}

#[link(name = "powloot_cuda", kind = "static")]
unsafe extern "C" {
    fn pow_gpu_cpu_hash_create(
        device_index: c_int,
        challenge: *const u8,
        challenge_len: usize,
        bits: u32,
    ) -> *mut PowGpuCpuHashJob;
    fn pow_gpu_cpu_hash_destroy(job: *mut PowGpuCpuHashJob);
    fn pow_gpu_cpu_hash_batch_size(job: *const PowGpuCpuHashJob) -> u32;
    fn pow_gpu_cpu_hash_run(
        job: *mut PowGpuCpuHashJob,
        nonce_prefix12: *const u8,
        out_nonce16: *mut u8,
    ) -> c_int;

    fn pow_gpu_chain_create(
        device_index: c_int,
        prefix: *const u8,
        prefix_len: usize,
        steps: u32,
        bits: u32,
    ) -> *mut PowGpuChainJob;
    fn pow_gpu_chain_destroy(job: *mut PowGpuChainJob);
    fn pow_gpu_chain_batch_size(job: *const PowGpuChainJob) -> u32;
    fn pow_gpu_chain_run(
        job: *mut PowGpuChainJob,
        nonce_prefix12: *const u8,
        out_nonce16: *mut u8,
    ) -> c_int;

    fn pow_gpu_branchy_create(
        device_index: c_int,
        prefix: *const u8,
        prefix_len: usize,
        rounds: u32,
        bits: u32,
    ) -> *mut PowGpuBranchyJob;
    fn pow_gpu_branchy_destroy(job: *mut PowGpuBranchyJob);
    fn pow_gpu_branchy_batch_size(job: *const PowGpuBranchyJob) -> u32;
    fn pow_gpu_branchy_run(
        job: *mut PowGpuBranchyJob,
        nonce_prefix12: *const u8,
        out_nonce16: *mut u8,
    ) -> c_int;

    fn pow_gpu_mem_work_create(
        device_index: c_int,
        init_mem: *const u8,
        total: usize,
        acc_prefix: *const u8,
        acc_prefix_len: usize,
        steps: u32,
        bits: u32,
    ) -> *mut PowGpuMemWorkJob;
    fn pow_gpu_mem_work_destroy(job: *mut PowGpuMemWorkJob);
    fn pow_gpu_mem_work_batch_size(job: *const PowGpuMemWorkJob) -> u32;
    fn pow_gpu_mem_work_run(
        job: *mut PowGpuMemWorkJob,
        nonce_prefix12: *const u8,
        out_nonce16: *mut u8,
    ) -> c_int;

    fn pow_gpu_tiny_vm_create(
        device_index: c_int,
        challenge: *const u8,
        challenge_len: usize,
        seed: *const u8,
        seed_len: usize,
        program: *const u8,
        program_len: usize,
        steps: u32,
        bits: u32,
    ) -> *mut PowGpuTinyVmJob;
    fn pow_gpu_tiny_vm_destroy(job: *mut PowGpuTinyVmJob);
    fn pow_gpu_tiny_vm_batch_size(job: *const PowGpuTinyVmJob) -> u32;
    fn pow_gpu_tiny_vm_run(
        job: *mut PowGpuTinyVmJob,
        nonce_prefix12: *const u8,
        out_nonce16: *mut u8,
    ) -> c_int;
}

pub struct GpuMiner {
    job: *mut Argon2GpuJob,
    batch_size: usize,
}

unsafe impl Send for GpuMiner {}

impl GpuMiner {
    pub fn device_count() -> anyhow::Result<usize> {
        let count = unsafe { argon2_gpu_device_count() };
        if count < 0 {
            anyhow::bail!("CUDA device enumeration failed");
        }
        Ok(count as usize)
    }

    pub fn device_name(index: usize) -> anyhow::Result<String> {
        let mut buf = [0i8; 256];
        let ret = unsafe { argon2_gpu_device_name(index as c_int, buf.as_mut_ptr(), buf.len()) };
        if ret < 0 {
            anyhow::bail!("Failed to read CUDA device name for index {}", index);
        }
        let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
        Ok(cstr.to_string_lossy().into_owned())
    }

    pub fn new(
        device_index: usize,
        salt: &[u8],
        memory_cost: u32,
        time_cost: u32,
        lanes: u32,
        jobs_per_block: u32,
        batch_size: usize,
    ) -> anyhow::Result<Self> {
        if salt.is_empty() {
            anyhow::bail!("salt is empty");
        }
        if batch_size == 0 {
            anyhow::bail!("batch_size must be > 0");
        }

        let job = unsafe {
            argon2_gpu_job_create(
                device_index as c_int,
                salt.as_ptr(),
                salt.len(),
                memory_cost,
                time_cost,
                lanes,
                jobs_per_block,
                batch_size,
            )
        };
        if job.is_null() {
            anyhow::bail!("failed to initialize CUDA miner");
        }

        let actual_batch = unsafe { argon2_gpu_job_batch_size(job) };
        if actual_batch == 0 {
            unsafe { argon2_gpu_job_destroy(job) };
            anyhow::bail!("CUDA miner returned batch size 0");
        }

        Ok(Self {
            job,
            batch_size: actual_batch,
        })
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn hash_batch(
        &mut self,
        pw_base: &[u8],
        pw_stride: usize,
        pw_lens: &[u32],
        batch: usize,
        out_hashes: &mut [u8],
    ) -> anyhow::Result<()> {
        if batch == 0 {
            return Ok(());
        }
        if batch > self.batch_size {
            anyhow::bail!("batch {} exceeds GPU batch size {}", batch, self.batch_size);
        }
        if pw_stride == 0 {
            anyhow::bail!("pw_stride must be > 0");
        }
        if pw_base.len() < pw_stride * batch {
            anyhow::bail!("pw_base too small for batch");
        }
        if pw_lens.len() < batch {
            anyhow::bail!("pw_lens too small for batch");
        }
        if out_hashes.len() < batch * 32 {
            anyhow::bail!("out_hashes too small for batch");
        }

        let rc = unsafe {
            argon2_gpu_hash_batch(
                self.job,
                pw_base.as_ptr(),
                pw_stride,
                pw_lens.as_ptr(),
                batch,
                out_hashes.as_mut_ptr(),
            )
        };
        if rc != 0 {
            anyhow::bail!("argon2_gpu_hash_batch failed with code {}", rc);
        }
        Ok(())
    }
}

impl Drop for GpuMiner {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { argon2_gpu_job_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub struct PowGpuCpuHash {
    job: *mut PowGpuCpuHashJob,
    batch_size: u32,
}

unsafe impl Send for PowGpuCpuHash {}

impl PowGpuCpuHash {
    pub fn new(device_index: usize, challenge: &[u8], bits: u32) -> anyhow::Result<Self> {
        if challenge.is_empty() {
            anyhow::bail!("challenge is empty");
        }
        let job = unsafe {
            pow_gpu_cpu_hash_create(device_index as c_int, challenge.as_ptr(), challenge.len(), bits)
        };
        if job.is_null() {
            anyhow::bail!("failed to init CUDA CPU_HASH job");
        }
        let batch_size = unsafe { pow_gpu_cpu_hash_batch_size(job) };
        if batch_size == 0 {
            unsafe { pow_gpu_cpu_hash_destroy(job) };
            anyhow::bail!("CPU_HASH batch size is 0");
        }
        Ok(Self { job, batch_size })
    }

    pub fn batch_size(&self) -> u32 {
        self.batch_size
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        let mut out = [0u8; 16];
        let rc = unsafe { pow_gpu_cpu_hash_run(self.job, nonce_prefix.as_ptr(), out.as_mut_ptr()) };
        if rc < 0 {
            anyhow::bail!("pow_gpu_cpu_hash_run failed with code {}", rc);
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(out))
    }
}

impl Drop for PowGpuCpuHash {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { pow_gpu_cpu_hash_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub struct PowGpuChain {
    job: *mut PowGpuChainJob,
    batch_size: u32,
}

unsafe impl Send for PowGpuChain {}

impl PowGpuChain {
    pub fn new(
        device_index: usize,
        prefix: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        if prefix.is_empty() {
            anyhow::bail!("prefix is empty");
        }
        let job = unsafe {
            pow_gpu_chain_create(device_index as c_int, prefix.as_ptr(), prefix.len(), steps, bits)
        };
        if job.is_null() {
            anyhow::bail!("failed to init CUDA CHAIN job");
        }
        let batch_size = unsafe { pow_gpu_chain_batch_size(job) };
        if batch_size == 0 {
            unsafe { pow_gpu_chain_destroy(job) };
            anyhow::bail!("CHAIN batch size is 0");
        }
        Ok(Self { job, batch_size })
    }

    pub fn batch_size(&self) -> u32 {
        self.batch_size
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        let mut out = [0u8; 16];
        let rc = unsafe { pow_gpu_chain_run(self.job, nonce_prefix.as_ptr(), out.as_mut_ptr()) };
        if rc < 0 {
            anyhow::bail!("pow_gpu_chain_run failed with code {}", rc);
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(out))
    }
}

impl Drop for PowGpuChain {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { pow_gpu_chain_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub struct PowGpuBranchyMix {
    job: *mut PowGpuBranchyJob,
    batch_size: u32,
}

unsafe impl Send for PowGpuBranchyMix {}

impl PowGpuBranchyMix {
    pub fn new(
        device_index: usize,
        prefix: &[u8],
        rounds: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        if prefix.is_empty() {
            anyhow::bail!("prefix is empty");
        }
        let job = unsafe {
            pow_gpu_branchy_create(
                device_index as c_int,
                prefix.as_ptr(),
                prefix.len(),
                rounds,
                bits,
            )
        };
        if job.is_null() {
            anyhow::bail!("failed to init CUDA BRANCHY_MIX job");
        }
        let batch_size = unsafe { pow_gpu_branchy_batch_size(job) };
        if batch_size == 0 {
            unsafe { pow_gpu_branchy_destroy(job) };
            anyhow::bail!("BRANCHY_MIX batch size is 0");
        }
        Ok(Self { job, batch_size })
    }

    pub fn batch_size(&self) -> u32 {
        self.batch_size
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        let mut out = [0u8; 16];
        let rc = unsafe { pow_gpu_branchy_run(self.job, nonce_prefix.as_ptr(), out.as_mut_ptr()) };
        if rc < 0 {
            anyhow::bail!("pow_gpu_branchy_run failed with code {}", rc);
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(out))
    }
}

impl Drop for PowGpuBranchyMix {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { pow_gpu_branchy_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub struct PowGpuMemWork {
    job: *mut PowGpuMemWorkJob,
    batch_size: u32,
}

unsafe impl Send for PowGpuMemWork {}

impl PowGpuMemWork {
    pub fn new(
        device_index: usize,
        init_mem: &[u8],
        acc_prefix: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        if init_mem.is_empty() {
            anyhow::bail!("init_mem is empty");
        }
        if acc_prefix.is_empty() {
            anyhow::bail!("acc_prefix is empty");
        }
        let job = unsafe {
            pow_gpu_mem_work_create(
                device_index as c_int,
                init_mem.as_ptr(),
                init_mem.len(),
                acc_prefix.as_ptr(),
                acc_prefix.len(),
                steps,
                bits,
            )
        };
        if job.is_null() {
            anyhow::bail!("failed to init CUDA MEM_WORK job");
        }
        let batch_size = unsafe { pow_gpu_mem_work_batch_size(job) };
        if batch_size == 0 {
            unsafe { pow_gpu_mem_work_destroy(job) };
            anyhow::bail!("MEM_WORK batch size is 0");
        }
        Ok(Self { job, batch_size })
    }

    pub fn batch_size(&self) -> u32 {
        self.batch_size
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        let mut out = [0u8; 16];
        let rc = unsafe { pow_gpu_mem_work_run(self.job, nonce_prefix.as_ptr(), out.as_mut_ptr()) };
        if rc < 0 {
            anyhow::bail!("pow_gpu_mem_work_run failed with code {}", rc);
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(out))
    }
}

impl Drop for PowGpuMemWork {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { pow_gpu_mem_work_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub struct PowGpuTinyVm {
    job: *mut PowGpuTinyVmJob,
    batch_size: u32,
}

unsafe impl Send for PowGpuTinyVm {}

impl PowGpuTinyVm {
    pub fn new(
        device_index: usize,
        challenge: &[u8],
        seed: &[u8],
        program: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        if challenge.is_empty() {
            anyhow::bail!("challenge is empty");
        }
        if seed.is_empty() {
            anyhow::bail!("seed is empty");
        }
        if program.is_empty() {
            anyhow::bail!("program is empty");
        }
        if program.len() % 4 != 0 {
            anyhow::bail!("program length must be multiple of 4");
        }
        let job = unsafe {
            pow_gpu_tiny_vm_create(
                device_index as c_int,
                challenge.as_ptr(),
                challenge.len(),
                seed.as_ptr(),
                seed.len(),
                program.as_ptr(),
                program.len(),
                steps,
                bits,
            )
        };
        if job.is_null() {
            anyhow::bail!("failed to init CUDA TINY_VM job");
        }
        let batch_size = unsafe { pow_gpu_tiny_vm_batch_size(job) };
        if batch_size == 0 {
            unsafe { pow_gpu_tiny_vm_destroy(job) };
            anyhow::bail!("TINY_VM batch size is 0");
        }
        Ok(Self { job, batch_size })
    }

    pub fn batch_size(&self) -> u32 {
        self.batch_size
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        let mut out = [0u8; 16];
        let rc = unsafe { pow_gpu_tiny_vm_run(self.job, nonce_prefix.as_ptr(), out.as_mut_ptr()) };
        if rc < 0 {
            anyhow::bail!("pow_gpu_tiny_vm_run failed with code {}", rc);
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(out))
    }
}

impl Drop for PowGpuTinyVm {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe { pow_gpu_tiny_vm_destroy(self.job) };
            self.job = ptr::null_mut();
        }
    }
}

pub enum PowGpuJob {
    CpuHash(PowGpuCpuHash),
    Chain(PowGpuChain),
    BranchyMix(PowGpuBranchyMix),
    MemWork(PowGpuMemWork),
    TinyVm(PowGpuTinyVm),
}

impl PowGpuJob {
    pub fn cpu_hash(device_index: usize, challenge: &[u8], bits: u32) -> anyhow::Result<Self> {
        Ok(Self::CpuHash(PowGpuCpuHash::new(device_index, challenge, bits)?))
    }

    pub fn chain(
        device_index: usize,
        prefix: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self::Chain(PowGpuChain::new(device_index, prefix, steps, bits)?))
    }

    pub fn branchy_mix(
        device_index: usize,
        prefix: &[u8],
        rounds: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self::BranchyMix(PowGpuBranchyMix::new(
            device_index,
            prefix,
            rounds,
            bits,
        )?))
    }

    pub fn mem_work(
        device_index: usize,
        init_mem: &[u8],
        acc_prefix: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self::MemWork(PowGpuMemWork::new(
            device_index,
            init_mem,
            acc_prefix,
            steps,
            bits,
        )?))
    }

    pub fn tiny_vm(
        device_index: usize,
        challenge: &[u8],
        seed: &[u8],
        program: &[u8],
        steps: u32,
        bits: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self::TinyVm(PowGpuTinyVm::new(
            device_index,
            challenge,
            seed,
            program,
            steps,
            bits,
        )?))
    }

    pub fn batch_size(&self) -> u32 {
        match self {
            Self::CpuHash(job) => job.batch_size(),
            Self::Chain(job) => job.batch_size(),
            Self::BranchyMix(job) => job.batch_size(),
            Self::MemWork(job) => job.batch_size(),
            Self::TinyVm(job) => job.batch_size(),
        }
    }

    pub fn run(&mut self, nonce_prefix: &[u8; 12]) -> anyhow::Result<Option<[u8; 16]>> {
        match self {
            Self::CpuHash(job) => job.run(nonce_prefix),
            Self::Chain(job) => job.run(nonce_prefix),
            Self::BranchyMix(job) => job.run(nonce_prefix),
            Self::MemWork(job) => job.run(nonce_prefix),
            Self::TinyVm(job) => job.run(nonce_prefix),
        }
    }
}
