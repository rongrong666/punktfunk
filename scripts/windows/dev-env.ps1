# punktfunk 本地开发环境变量（本机专用）—— 在 PowerShell 里执行: . .\scripts\windows\dev-env.ps1
# 然后 cargo 命令即可使用 MSVC 工具链。
$VS = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

# MSVC 编译环境（等价于 vcvars64.bat）
$vcvars = "$VS\VC\Auxiliary\Build\vcvars64.bat"
if (Test-Path $vcvars) {
    # 通过 cmd 导出 vcvars64 后的环境变量
    $envLines = cmd /c "`"$vcvars`" >nul 2>&1 && set"
    foreach ($line in $envLines) {
        if ($line -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
} else {
    Write-Warning "vcvars64.bat 未找到：$vcvars（VS Build Tools 尚未安装完成）"
}

# punktfunk 构建所需
$env:FFMPEG_DIR = "C:\Users\Public\ffmpeg"
$env:LIBCLANG_PATH = "C:\Users\dijia\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Lib\site-packages\clang\native"
$env:CARGO_TARGET_DIR = "C:\t"
$env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"

# PATH：cargo / nasm / VS 自带 cmake
$env:PATH = "$env:USERPROFILE\.cargo\bin;C:\Users\dijia\tools\nasm-2.16.03;$VS\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;" + $env:PATH

Write-Host "punktfunk 开发环境已就绪："
Write-Host "  rustc: $((rustc --version) 2>$null)"
Write-Host "  cmake: $((cmake --version) 2>$null | Select-Object -First 1)"
Write-Host "  FFMPEG_DIR = $env:FFMPEG_DIR"
Write-Host ""
Write-Host "构建命令："
Write-Host "  host:    cargo build --release -p punktfunk-host --features nvenc,amf-qsv,qsv"
Write-Host "  tray:    cargo build --release -p punktfunk-tray"
Write-Host "  client:  cargo build --release -p punktfunk-client-windows -p punktfunk-client-session -p punktfunk-cli --target x86_64-pc-windows-msvc"
