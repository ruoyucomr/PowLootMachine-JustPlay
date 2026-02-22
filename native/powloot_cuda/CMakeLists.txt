cmake_minimum_required(VERSION 3.18)

project(powloot_cuda LANGUAGES C CXX CUDA)

if(DEFINED ENV{CUDA_ARCH} AND NOT "$ENV{CUDA_ARCH}" STREQUAL "")
    set(CMAKE_CUDA_ARCHITECTURES $ENV{CUDA_ARCH})
elseif(NOT CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 89)
endif()

add_library(powloot_cuda STATIC powloot_cuda.cu)

set_target_properties(powloot_cuda PROPERTIES
    CUDA_STANDARD 11
    CUDA_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

# Silence noisy NVCC warnings on Windows
if(MSVC)
    target_compile_options(powloot_cuda PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/wd4244>
                                            $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/wd4267>)
endif()

install(TARGETS powloot_cuda ARCHIVE DESTINATION lib)
