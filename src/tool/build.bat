@echo off
REM Build revival_tool.exe -- 32-bit console application.
REM
REM Why 32-bit: dump-threads reads CONTEXT from Goley_'s (32-bit) threads.
REM A 64-bit tool would need Wow64GetThreadContext; staying x86 keeps the
REM code identical to Goley_'s register layout.

set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community
set VC_VARS=%VS_PATH%\VC\Auxiliary\Build\vcvars32.bat
if not exist "%VC_VARS%" (
    echo ERROR: vcvars32.bat not found at %VC_VARS%
    echo Install VS 2022 Build Tools or fix VS_PATH in this script.
    exit /b 1
)

call "%VC_VARS%"
cd /d "%~dp0"

cl.exe /nologo /EHsc /O2 /MT /W3 ^
    main.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
    user32.lib advapi32.lib shell32.lib psapi.lib ^
    /OUT:revival_tool.exe

cl.exe /nologo /EHsc /O2 /MT /W3 ^
    dummy_gg.cpp ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:X86 ^
    /OUT:dummy_gg.exe

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_tool.exe and dummy_gg.exe built ===
dir revival_tool.exe dummy_gg.exe
