@echo off
REM Build revival_patcher.dll (32-bit, Goley_.exe matches)
REM Requires Visual Studio 2022 Build Tools

set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community
set VC_VARS=%VS_PATH%\VC\Auxiliary\Build\vcvars32.bat

if not exist "%VC_VARS%" (
    echo ERROR: vcvars32.bat not found at %VC_VARS%
    exit /b 1
)

call "%VC_VARS%"

cd /d "%~dp0"

REM Compile MinHook C sources + our patcher.cpp into one DLL.
REM MinHook gives us a safe trampoline-based API hook framework
REM (used to intercept kernel32!CreateProcessA so we can inject
REM our DLL into the GameMon.des child that nProtect spawns).
cl.exe /nologo /LD /O2 /MT ^
    /Iminhook/include /Iminhook /Iminhook/hde /Icore /Ihooks /Ibypass /Imain ^
    main\*.cpp core\*.cpp hooks\*.cpp bypass\*.cpp ^
    minhook\hook.c ^
    minhook\buffer.c ^
    minhook\trampoline.c ^
    minhook\hde\hde32.c ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:X86 ^
    user32.lib kernel32.lib ws2_32.lib psapi.lib ^
    /OUT:revival_patcher.dll

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === revival_patcher.dll built ===
dir revival_patcher.dll
