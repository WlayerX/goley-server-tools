@echo off
REM Top-level build script: builds tool, patcher (DLL), and wrapper.
REM Each subproject has its own build.bat that calls vcvars32 internally,
REM so this driver just invokes them in sequence and checks ERRORLEVEL.
REM
REM Order:
REM   1. src/tool       --> revival_tool.exe         (32-bit console)
REM   2. src/patcher    --> revival_patcher.dll      (32-bit DLL, MinHook bundled)
REM   3. src/wrapper    --> revival_wrapper.exe      (32-bit GUI/console, IFEO target)
REM
REM Requires Visual Studio 2022 Build Tools (vcvars32.bat at the canonical path).

setlocal
set ROOT=%~dp0
set OK=1

echo.
echo === [1/3] Building revival_tool ===
pushd "%ROOT%src\tool"
call .\build.bat
if errorlevel 1 ( set OK=0 )
popd

echo.
echo === [2/3] Building revival_patcher.dll ===
pushd "%ROOT%src\patcher"
call .\build.bat
if errorlevel 1 ( set OK=0 )
popd

echo.
echo === [3/3] Building revival_wrapper.exe ===
pushd "%ROOT%src\wrapper"
call .\build.bat
if errorlevel 1 ( set OK=0 )
popd

echo.
if "%OK%"=="1" (
    echo === ALL BUILDS OK ===
    echo.
    echo Artifacts:
    if exist "%ROOT%src\tool\revival_tool.exe"          echo   src\tool\revival_tool.exe
    if exist "%ROOT%src\patcher\revival_patcher.dll"    echo   src\patcher\revival_patcher.dll
    if exist "%ROOT%src\wrapper\revival_wrapper.exe"    echo   src\wrapper\revival_wrapper.exe
    echo.
    echo Quick test:
    echo   src\tool\revival_tool.exe ping
    exit /b 0
) else (
    echo === BUILD FAILED -- see messages above ===
    exit /b 1
)
