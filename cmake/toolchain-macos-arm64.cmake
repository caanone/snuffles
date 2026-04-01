# Toolchain file for macOS arm64 (Apple Silicon)
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR arm64)

set(CMAKE_C_COMPILER clang)
set(CMAKE_OSX_ARCHITECTURES arm64)
