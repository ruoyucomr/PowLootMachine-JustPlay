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
- GPU acceleration is used for `CPU_HASH`, `CHAIN`, `BRANCHY_MIX`, `MEM_WORK`, `TINY_VM`, and `ARGON2D_CHAIN`. `VM_CHAIN` remains WASM/CPU.
- `--gpu-batch` only affects `ARGON2D_CHAIN`; other tracks use tuned CUDA batch sizes.
- `--gpu-jobs-per-block` can be used to fix argon2 CUDA jobs-per-block (power of two). Omit to auto-tune.
- GPU argon2 input assumes `salt = challenge + seed` and `password = nonce` (see `src/main.rs`).
- If the port is in use, start with `--port=<N>` and update `bridge.js`:
  `const RUST_URL = "http://localhost:<N>/";`

## Browser Bridge
1. Keep the Rust process running.
2. Open the target page in your browser.
3. Open DevTools Console and paste `bridge.js` from the repo root.
4. Allow popups for the site so the relay window can open.
