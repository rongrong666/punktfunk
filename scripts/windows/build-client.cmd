@echo off
rem punktfunk Windows 客户端构建脚本（本机环境）—— 客户端不链接 FFmpeg（M10 起原生解码）
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "PATH=C:\Users\dijia\.cargo\bin;C:\Users\dijia\tools\nasm-2.16.03;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "LIBCLANG_PATH=C:\Users\dijia\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Lib\site-packages\clang\native"
set "CARGO_TARGET_DIR=C:\t"
set "CMAKE_POLICY_VERSION_MINIMUM=3.5"
set "PUNKTFUNK_BUILD_VERSION=0.31.0"
set "SKIA_BINARIES_URL=file://C:/Users/dijia/tools/skia-binaries.tar.gz"
cd /d C:\Users\dijia\punktfunk
echo === build client ===
cargo build --release --locked -p punktfunk-client-windows -p punktfunk-client-session -p punktfunk-cli --target x86_64-pc-windows-msvc
if errorlevel 1 (echo CLIENT-BUILD-FAILED & exit /b 1)
echo CLIENT-ALL-DONE
