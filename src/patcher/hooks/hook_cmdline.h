#pragma once
#include "../core/globals.h"

LPSTR WINAPI HookedGetCommandLineA(void);
LPWSTR WINAPI HookedGetCommandLineW(void);
BOOL InitCmdLineHooks();
