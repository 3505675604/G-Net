@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title 服务器工具 - 一键安装

echo ==========================================
echo   服务器工具  一键安装
echo ==========================================
set "PY="
where py >nul 2>&1 && (py -3 -c "import sys" >nul 2>&1 && set "PY=py -3")
if not defined PY (
    where python >nul 2>&1 && (python -c "import sys" >nul 2>&1 && set "PY=python")
)
if not defined PY (
    echo [错误] 未找到 Python，请安装 Python 3.9 或更高版本并添加到 PATH。
    pause
    exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)"
if errorlevel 1 (
    echo [错误] 需要 Python 3.9 或更高版本。
    pause
    exit /b 1
)
echo [1/4] 检查 Python 完成。
if not exist "venv\Scripts\python.exe" (
    echo [2/4] 创建虚拟环境...
    %PY% -m venv venv
    if errorlevel 1 (
        echo [错误] 虚拟环境创建失败。
        pause
        exit /b 1
    )
) else (
    echo [2/4] 虚拟环境已存在。
)
echo [3/4] 安装依赖...
"venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo [错误] pip 更新失败，请检查网络。
    pause
    exit /b 1
)
"venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [错误] 依赖安装失败，请检查网络。
    pause
    exit /b 1
)
echo [4/4] 初始化配置文件与启动器...
if not exist "server-manager\servers.json" (
    copy /y "server-manager\servers.example.json" "server-manager\servers.json" >nul
    if errorlevel 1 (
        echo [错误] 服务器示例配置复制失败。
        pause
        exit /b 1
    )
)
if not exist "server-manager\settings.json" (
    copy /y "server-manager\settings.example.json" "server-manager\settings.json" >nul
    if errorlevel 1 (
        echo [错误] 设置示例配置复制失败。
        pause
        exit /b 1
    )
)
if not exist "launch_manager.py" (
    echo [错误] 未找到安全启动器 launch_manager.py，请恢复完整项目文件。
    pause
    exit /b 1
)
> "启动-服务器管家.bat" (
    echo @echo off
    echo chcp 65001 ^>nul
    echo setlocal
    echo cd /d "%%~dp0"
    echo "%%~dp0venv\Scripts\python.exe" "%%~dp0launch_manager.py"
    echo if errorlevel 1 ^(
    echo     pause
    echo     exit /b 1
    echo ^)
    echo exit /b 0
)
echo.
echo 安装完成，双击“启动-服务器管家.bat”打开管理面板。
echo 启动器会识别本项目实例；遇到其他程序占用端口时会提示。
pause
