@echo off
chcp 65001 >nul
echo 校园网自动认证助手 - 卸载脚本
echo ================================

echo.
echo 正在停止程序进程...
taskkill /f /im "campus-net-auth.exe" >nul 2>&1

echo.
echo 正在删除开机自启动项...
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "CampusNetAuth" /f >nul 2>&1

echo.
echo 正在删除桌面快捷方式...
set "desktop=%USERPROFILE%\Desktop"
set "shortcut=%desktop%\校园网认证助手.lnk"
if exist "%shortcut%" (
    del "%shortcut%"
    echo 桌面快捷方式已删除
) else (
    echo 桌面快捷方式不存在
)

echo.
echo 正在删除用户数据...
set "userData=%USERPROFILE%\CampusNetAuth"
if exist "%userData%" (
    rmdir /s /q "%userData%"
    echo 用户数据已删除
) else (
    echo 用户数据不存在
)

echo.
echo 卸载完成！
echo.
echo 注意: 程序文件需要手动删除
echo.

pause
