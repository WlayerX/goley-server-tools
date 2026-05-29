#include "hook_cmdline.h"
#include "../core/logger.h"
#include "../core/helpers.h"

LPSTR WINAPI HookedGetCommandLineA(void) {
    if (InterlockedExchange(&g_gclLogged, 1) == 0) {
        char buf[200];
        wsprintfA(buf, "GetCommandLineA called -> fake '%s'", g_fakeCmdLineA);
        Log(buf);
    }
    return g_fakeCmdLineA;
}


LPWSTR WINAPI HookedGetCommandLineW(void) {
    return g_fakeCmdLineW;
}


BOOL InitCmdLineHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) return FALSE;
    PVOID p1 = GetProcAddress(hKernel, "GetCommandLineA");
    PVOID p2 = GetProcAddress(hKernel, "GetCommandLineW");
    char buf[256];
    wsprintfA(buf, "GetCommandLine targets: A=0x%p W=0x%p", p1, p2);
    Log(buf);
    BOOL ok = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedGetCommandLineA,
                                    (LPVOID*)&g_origGetCommandLineA);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("GetCommandLineA hook ENABLED"); ok = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedGetCommandLineW,
                                    (LPVOID*)&g_origGetCommandLineW);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("GetCommandLineW hook ENABLED"); ok = TRUE;
        }
    }
    return ok;
}


