@echo off
REM Build revival_wrapper.exe (32-bit so it matches Goley_.exe arch).
REM IFEO Debugger key will invoke this binary in front of Goley_.exe.

set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community
set VC_VARS=%VS_PATH%\VC\Auxiliary\Build\vcvars32.bat

if not exist "%VC_VARS%" (
    echo ERROR: vcvars32.bat not found at %VC_VARS%
    exit /b 1
)

call "%VC_VARS%"
cd /d "%~dp0"

REM /MT = static CRT so the wrapper has zero install deps.
REM /EHsc = standard C++ exception model for std::wstring.
cl.exe /nologo /O2 /MT /EHsc ^
    wrapper.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
    user32.lib kernel32.lib ^
    /OUT:revival_wrapper.exe

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_wrapper.exe built ===
dir revival_wrapper.exe
