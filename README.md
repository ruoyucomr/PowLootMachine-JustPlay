# PowLoot Machine (CPU + CUDA)

## Prerequisites
- Rust toolchain (stable)
- Visual Studio 2022 Build Tools (C++ workload)
- CMake
- NVIDIA CUDA Toolkit (for GPU build)
- PowLoot WASM asset: `powloot_wasm.wasm-0002330e`

WASM location:
- Default: `PowLoot/static/wasm/powloot_wasm.wasm-0002330e`
- Or set `POWLOOT_WASM` to the full file path

## Build
### CPU
```powershell
C:\Users\ruoyu\.cargo\bin\cargo.exe build --release
```

### CUDA (GPU)
```powershell
# Optional: set CUDA_PATH if not already present
$env:CUDA_PATH="C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
$env:Path="C:\Program Files\CMake\bin;C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\bin;" + $env:Path

C:\Users\ruoyu\.cargo\bin\cargo.exe build --release --features cuda
```

## Run
### CPU
```powershell
.\target\release\powloot-machine.exe
```

### CUDA (GPU)
```powershell
.\target\release\powloot-machine.exe --gpu --gpu-device=0 --gpu-batch=256
```

Notes:
- GPU acceleration is used for `CPU_HASH`, `CHAIN`, `BRANCHY_MIX`, `MEM_WORK`, and `TINY_VM`.
- `ARGON2D_CHAIN` and `VM_CHAIN` use WASM/CPU.
- `--gpu-batch` and `--gpu-jobs-per-block` are currently unused (ARGON2D_CHAIN is forced to WASM/CPU).
- If the port is in use, start with `--port=<N>` and update `bridge.js`:
  `const RUST_URL = "http://localhost:<N>/";`

### CPU Tuning (Windows)
By default, the miner reserves CPU cores to reduce system freezes:
- `>= 8` logical cores: reserve 2 cores
- `< 8` logical cores: reserve 1 core

Override or tune:
- `--threads=<N>`: manual thread count
- `--cpu-priority=<idle|below_normal|normal|above_normal|high|realtime>`
- `--cpu-affinity=<mask>` (decimal or `0x..`)

## Browser Bridge
1. Keep the Rust process running.
2. Open the target page in your browser.
3. Open DevTools Console and paste `bridge.js` from the repo root.
4. Allow popups for the site so the relay window can open.
