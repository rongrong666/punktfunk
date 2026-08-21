@echo off
rem 本机 cargo 开发环境包装：vcvars64 + nasm/cmake/ninja + FFmpeg + libclang + SKIA
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=C:\Users\dijia\.cargo\bin;C:\Users\dijia\tools\nasm-2.16.03;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "FFMPEG_DIR=C:\Users\Public\ffmpeg"
set "PATH=C:\Users\Public\ffmpeg\bin;%PATH%"
set "LIBCLANG_PATH=C:\Users\dijia\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Lib\site-packages\clang\native"
set "SKIA_BINARIES_URL=file://C:/Users/dijia/tools/skia-binaries.tar.gz"
set "CARGO_TARGET_DIR=C:\t"
set "CMAKE_POLICY_VERSION_MINIMUM=3.5"
set "PUNKTFUNK_BUILD_VERSION=0.31.0"
cd /d C:\Users\dijia\punktfunk
cargo %*
