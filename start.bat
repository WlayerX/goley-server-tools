@echo off
chcp 65001 >nul 2>&1
title Goley Revival - Baslatici
color 0A

echo ============================================
echo   GOLEY REVIVAL BASLATICI
echo ============================================
echo.

:: Admin kontrolu
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [HATA] Bu dosyayi SAG TIKLA ve "Yonetici olarak calistir" sec!
    echo.
    pause
    exit /b 1
)

echo [OK] Admin yetkileri mevcut
echo.

:: IFEO temizle
echo [1/5] IFEO temizleniyor...
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Goley_.exe" /v Debugger /f >nul 2>&1
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Goley_.exe" /v Debugger /f >nul 2>&1
echo       IFEO temizlendi.
echo.

:: Eski processleri temizle
echo [2/5] Eski processler temizleniyor...
taskkill /f /im Goley_.exe >nul 2>&1
taskkill /f /im GoleyGame.exe >nul 2>&1
taskkill /f /im revival_wrapper.exe >nul 2>&1
timeout /t 1 /nobreak >nul
echo       Temizlendi.
echo.

:: Serverlari baslat
echo [3/5] Serverlar baslatiliyor...
set SERVERBIN=%~dp0server\bin
set SERVERDIR=%~dp0server

start /min "" "%SERVERBIN%\entry-server.exe"
start /min "" "%SERVERBIN%\lobby-server.exe"
start /min "" "%SERVERBIN%\battle-server.exe"
start /min "" "%SERVERBIN%\daum-auth.exe"
start /min "" "%SERVERBIN%\launcher-web.exe"
start /min "" "%SERVERBIN%\patch-server.exe" -game-dir "C:\Joygame\Goley"
timeout /t 2 /nobreak >nul
echo       6 server baslatildi.
echo.

:: Log temizle
echo [4/5] Eski loglar temizleniyor...
del /f /q "%~dp0patcher*.log" >nul 2>&1
echo       Loglar temizlendi.
echo.

:: Oyunu baslat
echo [5/5] Goley baslatiliyor...
echo.
echo       GameGuard sahtelestiriliyor...
if not exist "C:\Joygame\Goley\BinaryTr\GameGuard.des.bak" (
    copy /y "C:\Joygame\Goley\BinaryTr\GameGuard.des" "C:\Joygame\Goley\BinaryTr\GameGuard.des.bak" >nul 2>&1
)
copy /y "%~dp0src\tool\dummy_gg.exe" "C:\Joygame\Goley\BinaryTr\GameGuard.des" >nul 2>&1

"%~dp0src\tool\revival_tool.exe" launch
echo.

echo ============================================
echo   Oyun baslatildi!
echo   patcher.log dosyasini izle:
echo   %~dp0patcher.log
echo ============================================
echo.

:: 90 saniye izle
echo Loglar izleniyor (90 saniye)...
echo.
for /L %%i in (1,1,18) do (
    timeout /t 5 /nobreak >nul
    if exist "%~dp0patcher.log" (
        echo [%%i] patcher.log mevcut
        type "%~dp0patcher.log" | find /c /v "" 
    )
    tasklist /fi "imagename eq Goley_.exe" /nh 2>nul | find /i "Goley_" >nul
    if errorlevel 1 (
        echo [%%i] Goley process bulunamadi
    ) else (
        echo [%%i] Goley CALISIYOR
    )
)

echo.
echo ============================================
echo   LOG CIKTISI:
echo ============================================
echo.
if exist "%~dp0patcher.log" (
    type "%~dp0patcher.log"
) else (
    echo patcher.log bulunamadi!
)
echo.
if exist "%~dp0patcher_wrapper.log" (
    echo --- patcher_wrapper.log ---
    type "%~dp0patcher_wrapper.log"
)
if exist "%~dp0patcher_payload.log" (
    echo --- patcher_payload.log ---
    type "%~dp0patcher_payload.log"
)

echo.
pause
