#include "hook_bugtrap.h"
#include "../core/logger.h"
#include "../core/helpers.h"

int __stdcall HookedBT_SaveSnapshot(void* excPtrs, const char* fname) {
    if (EnterHook()) {
        char buf[320];
        wsprintfA(buf, "BT_SaveSnapshot INTERCEPT exc=0x%p fname='%.220s' -> ret 1",
                  excPtrs, fname ? fname : "<null>");
        Log(buf);
        LeaveHook();
    }
    return 1;  // BugTrap convention: non-zero = success
}


int __stdcall HookedBT_SendSnapshot(void* excPtrs, const char* fname) {
    if (EnterHook()) {
        char buf[320];
        wsprintfA(buf, "BT_SendSnapshot INTERCEPT exc=0x%p fname='%.220s' -> ret 1",
                  excPtrs, fname ? fname : "<null>");
        Log(buf);
        LeaveHook();
    }
    return 1;
}


void __stdcall HookedBT_SetFlags(DWORD dwFlags) {
    if (EnterHook()) {
        char buf[120];
        wsprintfA(buf, "BT_SetFlags(0x%X) INTERCEPT -> forcing 0 (silent mode)",
                  dwFlags);
        Log(buf);
        LeaveHook();
    }
    // Original API cagrilir ama her zaman 0 ile -> UI yok, sadece log.
    if (g_origBT_SetFlags) g_origBT_SetFlags(0);
}


BOOL InitBugTrapHooks() {
    HMODULE hBT = GetModuleHandleA("BugTrap.dll");
    if (!hBT) return FALSE;
    PVOID p1 = GetProcAddress(hBT, "BT_SaveSnapshot");
    PVOID p2 = GetProcAddress(hBT, "BT_SendSnapshot");
    PVOID p3 = GetProcAddress(hBT, "BT_SetFlags");
    char buf[256];
    wsprintfA(buf, "BugTrap targets: Save=0x%p Send=0x%p SetFlags=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedBT_SaveSnapshot,
                                    (LPVOID*)&g_origBT_SaveSnapshot);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("BT_SaveSnapshot hook ENABLED (dialog tetikleyicisi bypass)");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SaveSnapshot hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedBT_SendSnapshot,
                                    (LPVOID*)&g_origBT_SendSnapshot);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("BT_SendSnapshot hook ENABLED");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SendSnapshot hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedBT_SetFlags,
                                    (LPVOID*)&g_origBT_SetFlags);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("BT_SetFlags hook ENABLED (silent mode zorlandi)");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SetFlags hook FAILED status=%d", s); Log(buf);
        }
    }
    return anyOk;
}


