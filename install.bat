@echo off
chcp 65001 >nul
echo 校园网自动认证助手 - 安装脚本
echo ================================

echo.
echo 正在检查程序文件...
if not exist "campus-net-auth.exe" (
    echo 错误: 找不到 campus-net-auth.exe 文件
    echo 请确保程序文件在当前目录中
    pause
    exit /b 1
)

echo 程序文件检查完成

echo.
echo 正在创建桌面快捷方式...
set "desktop=%USERPROFILE%\Desktop"
set "shortcut=%desktop%\校园网认证助手.lnk"

powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%shortcut%'); $Shortcut.TargetPath = '%~dp0campus-net-auth.exe'; $Shortcut.WorkingDirectory = '%~dp0'; $Shortcut.Description = '校园网自动认证助手'; $Shortcut.Save()"

if exist "%shortcut%" (
    echo 桌面快捷方式创建成功
) else (
    echo 桌面快捷方式创建失败
)

echo.
echo 正在设置开机自启动...
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "CampusNetAuth" /t REG_SZ /d "%~dp0campus-net-auth.exe" /f >nul 2>&1

if %errorlevel% == 0 (
    echo 开机自启动设置成功
) else (
    echo 开机自启动设置失败，请以管理员身份运行此脚本
)

echo.
echo 安装完成！
echo.
echo 使用说明:
echo 1. 双击桌面快捷方式启动程序
echo 2. 首次运行会自动打开配置页面
echo 3. 输入校园网账号密码并保存
echo 4. 程序将在系统托盘中运行
echo.
echo 注意: 程序会自动隐藏到系统托盘，右键托盘图标可进行配置
echo.

pause
