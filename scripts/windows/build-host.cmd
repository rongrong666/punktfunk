@echo off
rem punktfunk host + tray 构建脚本（本机环境）
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "PATH=C:\Users\dijia\.cargo\bin;C:\Users\dijia\tools\nasm-2.16.03;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "FFMPEG_DIR=C:\Users\Public\ffmpeg"
set "PATH=C:\Users\Public\ffmpeg\bin;%PATH%"
set "LIBCLANG_PATH=C:\Users\dijia\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Lib\site-packages\clang\native"
set "CARGO_TARGET_DIR=C:\t"
set "CMAKE_POLICY_VERSION_MINIMUM=3.5"
set "PUNKTFUNK_BUILD_VERSION=0.31.0"
cd /d C:\Users\dijia\punktfunk
echo === rustc / cmake ===
rustc --version
cmake --version
echo === build host ===
cargo build --release --locked -p punktfunk-host --features nvenc,amf-qsv,qsv
if errorlevel 1 (echo HOST-BUILD-FAILED & exit /b 1)
echo === build tray ===
cargo build --release --locked -p punktfunk-tray
if errorlevel 1 (echo TRAY-BUILD-FAILED & exit /b 1)
echo BUILD-ALL-DONE
