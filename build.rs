use std::env;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_FEATURE_CUDA").is_err() {
        return;
    }

    println!("cargo:rerun-if-env-changed=ARGON2_GPU_DIR");
    println!("cargo:rerun-if-env-changed=CUDA_PATH");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let argon2_dir = env::var("ARGON2_GPU_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("third_party").join("argon2-gpu"));

    if !argon2_dir.exists() {
        panic!(
            "argon2-gpu not found at {} (set ARGON2_GPU_DIR to override)",
            argon2_dir.display()
        );
    }
    println!("cargo:rerun-if-changed={}", argon2_dir.join("CMakeLists.txt").display());
    println!(
        "cargo:rerun-if-changed={}",
        argon2_dir
            .join("include")
            .join("argon2-cuda")
            .join("processingunit.h")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        argon2_dir
            .join("lib")
            .join("argon2-cuda")
            .join("processingunit.cpp")
            .display()
    );

    let mut cfg = cmake::Config::new(&argon2_dir);
    cfg.define("NO_CUDA", "OFF")
        .define("ARGON2_GPU_BUILD_OPENCL", "OFF")
        .define("ARGON2_GPU_BUILD_TOOLS", "OFF")
        .define("ARGON2_BUILD_TOOLS", "OFF")
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .define("CMAKE_BUILD_TYPE", "Release");

    let dst = cfg.build();

    let lib_dir = dst.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=argon2-cuda");
    println!("cargo:rustc-link-lib=static=argon2-gpu-common");

    let powloot_cuda_dir = manifest_dir.join("native").join("powloot_cuda");
    if !powloot_cuda_dir.exists() {
        panic!(
            "powloot_cuda not found at {}",
            powloot_cuda_dir.display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        powloot_cuda_dir.join("CMakeLists.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        powloot_cuda_dir.join("powloot_cuda.cu").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        powloot_cuda_dir.join("powloot_cuda.h").display()
    );

    let mut pow_cfg = cmake::Config::new(&powloot_cuda_dir);
    pow_cfg.define("CMAKE_BUILD_TYPE", "Release");
    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        pow_cfg.define("CUDAToolkit_ROOT", cuda_path);
    }
    let pow_dst = pow_cfg.build();
    let pow_lib_dir = pow_dst.join("lib");
    println!("cargo:rustc-link-search=native={}", pow_lib_dir.display());
    println!("cargo:rustc-link-lib=static=powloot_cuda");

    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        let cuda_lib = PathBuf::from(cuda_path).join("lib").join("x64");
        println!("cargo:rustc-link-search=native={}", cuda_lib.display());
        println!("cargo:rustc-link-lib=dylib=cudart");
        println!("cargo:rustc-link-lib=dylib=cuda");
    }

    let wrapper = manifest_dir.join("native").join("argon2_cuda_wrapper.cpp");
    let wrapper_h = manifest_dir.join("native").join("argon2_cuda_wrapper.h");
    println!("cargo:rerun-if-changed={}", wrapper.display());
    println!("cargo:rerun-if-changed={}", wrapper_h.display());

    let mut build = cc::Build::new();
    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        build.include(PathBuf::from(cuda_path).join("include"));
    }
    build
        .cpp(true)
        .file(wrapper)
        .define("HAVE_CUDA", Some("1"))
        .include(argon2_dir.join("include"))
        .include(argon2_dir.join("lib"))
        .include(argon2_dir.join("ext").join("argon2").join("include"))
        .flag_if_supported("/std:c++17")
        .compile("argon2_cuda_wrapper");
}
