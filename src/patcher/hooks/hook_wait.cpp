#include "hook_wait.h"
#include "../core/logger.h"
#include "../core/helpers.h"

DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout) {
    static volatile LONG ggBypassed = 0;
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    
    if (ggBypassed == 0 && EnterHook()) {
        char name[300];
        char buf[600];
        DescribeHandle(hObj, name, sizeof(name));
        
        if (longWait) {
            wsprintfA(buf, "[WFSO] TID=%lu h=0x%p timeout=%lu name='%s' caller=0x%p",
                      GetCurrentThreadId(), hObj, dwTimeout, name, _ReturnAddress());
            Log(buf);
        }

        // nProtect event auto-signal: GameMon.des normalde bu event'i
        // signal eder. Biz GameMon'u calistirmiyoruz, bu yuzden event
        // asla signal edilmiyor ve oyun splash'ta takiliyor.
        // Pattern tespiti: handle adi nProtect ile ilgili mi?
        BOOL isNProtectEvent = FALSE;
        const char* patterns[] = {"NPG", "GameMon", "nProtect", "GameGuard", "INCA", NULL};
        for (int i = 0; patterns[i]; i++) {
            // Case-insensitive substring search
            const char* p = name;
            const char* needle = patterns[i];
            int nlen = lstrlenA(needle);
            while (*p) {
                BOOL match = TRUE;
                for (int j = 0; j < nlen && p[j]; j++) {
                    char a = p[j]; char b = needle[j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) { isNProtectEvent = TRUE; break; }
                p++;
            }
            if (isNProtectEvent) break;
        }

        if (isNProtectEvent) {
            char buf2[600];
            wsprintfA(buf2, "  *** nProtect EVENT DETECTED: '%s' (timeout=%lu) -- auto-signaling ***", name, dwTimeout);
            Log(buf2);
            SetEvent(hObj);
            InterlockedExchange(&ggBypassed, 1);
        }
        // Isimsiz handle + INFINITE timeout: nProtect anonim event
        // kullanabilir. Ilk 90 sn icinde 100ms poll ile dene, sonra
        // orijinal INFINITE'e birak.
        else if (dwTimeout == INFINITE && lstrcmpA(name, "<unnamed>") == 0) {
            // UNBOUNDED timed-poll. The old code only polled the first 20 anon
            // waits for 90s then surrendered to native INFINITE; the 21st+ fell
            // straight through to g_origWFSO(INFINITE) and parked FOREVER at
            // ntdll+0x7B03C (the observed deadlock). We never hand INFINITE to
            // the native stub: poll at 250ms so the thread stays interruptible
            // and wakes the instant the object signals.
            static volatile LONG g_anonWaitCount = 0;
            LONG anonIdx = InterlockedIncrement(&g_anonWaitCount);
            BOOL logThis = (anonIdx <= 20);
            if (logThis) {
                wsprintfA(buf, "  anon-INFINITE wait #%ld -- 250ms timed-poll (never native INFINITE)", anonIdx);
                Log(buf);
            }
            LeaveHook();
            DWORD waited = 0;
            for (;;) {
                DWORD r = g_origWFSO(hObj, 250);
                if (r != WAIT_TIMEOUT) {
                    if (logThis && EnterHook()) {
                        wsprintfA(buf, "  anon wait #%ld signaled (r=%lu) after ~%lu ms",
                                  anonIdx, r, waited);
                        Log(buf);
                        LeaveHook();
                    }
                    return r;
                }
                waited += 250;
                // ~30s heartbeat so a genuinely stuck wait is visible, not silent.
                if ((waited % 30000) == 0 && EnterHook()) {
                    wsprintfA(buf, "  anon wait #%ld still blocked after %lu ms (poll continues)",
                              anonIdx, waited);
                    Log(buf);
                    LeaveHook();
                }
            }
        }
        LeaveHook();
    }
    DWORD r = g_origWFSO(hObj, dwTimeout);
    if (longWait && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSO] TID=%lu h=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}


DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout,
                                                BOOL bAlertable) {
    static volatile LONG ggBypassedEx = 0;
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    
    if (ggBypassedEx == 0 && EnterHook()) {
        char name[300];
        char buf[600];
        DescribeHandle(hObj, name, sizeof(name));
        
        if (longWait) {
            wsprintfA(buf, "[WFSOEx] TID=%lu h=0x%p timeout=%lu alertable=%d name='%s' caller=0x%p",
                      GetCurrentThreadId(), hObj, dwTimeout, bAlertable, name,
                      _ReturnAddress());
            Log(buf);
        }

        // nProtect auto-signal (ayni mantik WFSO ile)
        BOOL isNProtectEvent = FALSE;
        const char* patterns[] = {"NPG", "GameMon", "nProtect", "GameGuard", "INCA", NULL};
        for (int i = 0; patterns[i]; i++) {
            const char* p = name;
            const char* needle = patterns[i];
            int nlen = lstrlenA(needle);
            while (*p) {
                BOOL match = TRUE;
                for (int j = 0; j < nlen && p[j]; j++) {
                    char a = p[j]; char b = needle[j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) { isNProtectEvent = TRUE; break; }
                p++;
            }
            if (isNProtectEvent) break;
        }

        if (isNProtectEvent) {
            char buf2[600];
            wsprintfA(buf2, "  *** nProtect EVENT (Ex) DETECTED: '%s' -- auto-signaling ***", name);
            Log(buf2);
            SetEvent(hObj);
            InterlockedExchange(&ggBypassedEx, 1);
        }
        // Mirror the WFSO anon-INFINITE guard: never let an anonymous INFINITE
        // wait park forever at the native stub (ntdll+0x7B03C). 250ms timed-poll
        // keeps the thread interruptible; honors bAlertable on each slice.
        else if (dwTimeout == INFINITE && lstrcmpA(name, "<unnamed>") == 0) {
            static volatile LONG g_anonWaitCountEx = 0;
            LONG anonIdx = InterlockedIncrement(&g_anonWaitCountEx);
            BOOL logThis = (anonIdx <= 20);
            if (logThis) {
                wsprintfA(buf, "  anon-INFINITE wait (Ex) #%ld -- 250ms timed-poll (never native INFINITE)", anonIdx);
                Log(buf);
            }
            LeaveHook();
            DWORD waited = 0;
            for (;;) {
                DWORD r = g_origWFSOEx(hObj, 250, bAlertable);
                if (r != WAIT_TIMEOUT) {
                    if (logThis && EnterHook()) {
                        wsprintfA(buf, "  anon wait (Ex) #%ld signaled (r=%lu) after ~%lu ms",
                                  anonIdx, r, waited);
                        Log(buf);
                        LeaveHook();
                    }
                    return r;
                }
                waited += 250;
                if ((waited % 30000) == 0 && EnterHook()) {
                    wsprintfA(buf, "  anon wait (Ex) #%ld still blocked after %lu ms (poll continues)",
                              anonIdx, waited);
                    Log(buf);
                    LeaveHook();
                }
            }
        }
        LeaveHook();
    }
    DWORD r = g_origWFSOEx(hObj, dwTimeout, bAlertable);
    if (longWait && EnterHook()) {
        char buf[200];
        wsprintfA(buf, "  [WFSOEx] TID=%lu h=0x%p -> %lu",
                  GetCurrentThreadId(), hObj, r);
        Log(buf);
        LeaveHook();
    }
    return r;
}


DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount,
                                                  const HANDLE* pHandles,
                                                  BOOL bWaitAll,
                                                  DWORD dwTimeout) {
    if (g_hGameMonProcess && pHandles && !bWaitAll && nCount == 2) {
        int gameMonIndex = -1;
        for (DWORD i = 0; i < nCount; i++) {
            if (pHandles[i] == g_hGameMonProcess) {
                gameMonIndex = i;
                break;
            }
        }
        
        if (gameMonIndex != -1) {
            int eventIndex = (gameMonIndex == 0) ? 1 : 0;
            HANDLE hEvent = pHandles[eventIndex];
            
            if (EnterHook()) {
                char buf[256];
                wsprintfA(buf, "  *** GameMon WFMO detected! Auto-signaling event h=0x%p ***", hEvent);
                Log(buf);
                LeaveHook();
            }
            
            SetEvent(hEvent);
            return WAIT_OBJECT_0 + eventIndex;
        }
    }

    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[WFMO] TID=%lu n=%lu waitAll=%d timeout=%lu",
                            GetCurrentThreadId(), nCount, bWaitAll, dwTimeout);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            DescribeHandle(pHandles[i], name, sizeof(name));
            off += wsprintfA(buf + off, "; h%lu=0x%p '%.200s'",
                             i, pHandles[i], name);
        }
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFMO(nCount, pHandles, bWaitAll, dwTimeout);
    if (longWait && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [WFMO] TID=%lu -> %lu", GetCurrentThreadId(), r);
        Log(buf);
        LeaveHook();
    }
    return r;
}


DWORD WINAPI HookedWaitForMultipleObjectsEx(DWORD nCount,
                                            const HANDLE* pHandles,
                                            BOOL bWaitAll,
                                            DWORD dwTimeout,
                                            BOOL bAlertable) {
    if (g_hGameMonProcess && pHandles && !bWaitAll && nCount == 2) {
        int gameMonIndex = -1;
        for (DWORD i = 0; i < nCount; i++) {
            if (pHandles[i] == g_hGameMonProcess) {
                gameMonIndex = i;
                break;
            }
        }
        
        if (gameMonIndex != -1) {
            int eventIndex = (gameMonIndex == 0) ? 1 : 0;
            HANDLE hEvent = pHandles[eventIndex];
            
            if (EnterHook()) {
                char buf[256];
                wsprintfA(buf, "  *** GameMon WFMOEx detected! Auto-signaling event h=0x%p ***", hEvent);
                Log(buf);
                LeaveHook();
            }
            
            SetEvent(hEvent);
            return WAIT_OBJECT_0 + eventIndex;
        }
    }

    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[WFMOEx] TID=%lu n=%lu waitAll=%d timeout=%lu alertable=%d",
                            GetCurrentThreadId(), nCount, bWaitAll, dwTimeout, bAlertable);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            DescribeHandle(pHandles[i], name, sizeof(name));
            off += wsprintfA(buf + off, "; h%lu=0x%p '%.200s'",
                             i, pHandles[i], name);
        }
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origWFMOEx(nCount, pHandles, bWaitAll, dwTimeout, bAlertable);
    if (longWait && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [WFMOEx] TID=%lu -> %lu", GetCurrentThreadId(), r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

DWORD WINAPI HookedMsgWaitForMultipleObjects(DWORD nCount,
                                             const HANDLE* pHandles,
                                             BOOL fWaitAll,
                                             DWORD dwTimeout,
                                             DWORD dwWakeMask) {
    if (g_hGameMonProcess && pHandles && !fWaitAll && nCount == 2) {
        int gameMonIndex = -1;
        for (DWORD i = 0; i < nCount; i++) {
            if (pHandles[i] == g_hGameMonProcess) {
                gameMonIndex = i;
                break;
            }
        }
        
        if (gameMonIndex != -1) {
            int eventIndex = (gameMonIndex == 0) ? 1 : 0;
            HANDLE hEvent = pHandles[eventIndex];
            
            if (EnterHook()) {
                char buf[256];
                wsprintfA(buf, "  *** GameMon MsgWFMO detected! Auto-signaling event h=0x%p ***", hEvent);
                Log(buf);
                LeaveHook();
            }
            
            SetEvent(hEvent);
            return WAIT_OBJECT_0 + eventIndex;
        }
    }

    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[MsgWFMO] TID=%lu n=%lu waitAll=%d timeout=%lu wakeMask=0x%X",
                            GetCurrentThreadId(), nCount, fWaitAll, dwTimeout, dwWakeMask);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            DescribeHandle(pHandles[i], name, sizeof(name));
            off += wsprintfA(buf + off, "; h%lu=0x%p '%.200s'",
                             i, pHandles[i], name);
        }
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origMsgWFMO(nCount, pHandles, fWaitAll, dwTimeout, dwWakeMask);
    if (longWait && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [MsgWFMO] TID=%lu -> %lu", GetCurrentThreadId(), r);
        Log(buf);
        LeaveHook();
    }
    return r;
}

DWORD WINAPI HookedMsgWaitForMultipleObjectsEx(DWORD nCount,
                                               const HANDLE* pHandles,
                                               DWORD dwTimeout,
                                               DWORD dwWakeMask,
                                               DWORD dwFlags) {
    if (g_hGameMonProcess && pHandles && nCount == 2) {
        int gameMonIndex = -1;
        for (DWORD i = 0; i < nCount; i++) {
            if (pHandles[i] == g_hGameMonProcess) {
                gameMonIndex = i;
                break;
            }
        }
        
        if (gameMonIndex != -1) {
            int eventIndex = (gameMonIndex == 0) ? 1 : 0;
            HANDLE hEvent = pHandles[eventIndex];
            
            if (EnterHook()) {
                char buf[256];
                wsprintfA(buf, "  *** GameMon MsgWFMOEx detected! Auto-signaling event h=0x%p ***", hEvent);
                Log(buf);
                LeaveHook();
            }
            
            SetEvent(hEvent);
            return WAIT_OBJECT_0 + eventIndex;
        }
    }

    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && pHandles && EnterHook()) {
        char buf[2048];
        int off = wsprintfA(buf, "[MsgWFMOEx] TID=%lu n=%lu timeout=%lu wakeMask=0x%X flags=0x%X",
                            GetCurrentThreadId(), nCount, dwTimeout, dwWakeMask, dwFlags);
        for (DWORD i = 0; i < nCount && i < 8 && off < 1900; i++) {
            char name[280];
            DescribeHandle(pHandles[i], name, sizeof(name));
            off += wsprintfA(buf + off, "; h%lu=0x%p '%.200s'",
                             i, pHandles[i], name);
        }
        Log(buf);
        LeaveHook();
    }
    DWORD r = g_origMsgWFMOEx(nCount, pHandles, dwTimeout, dwWakeMask, dwFlags);
    if (longWait && EnterHook()) {
        char buf[160];
        wsprintfA(buf, "  [MsgWFMOEx] TID=%lu -> %lu", GetCurrentThreadId(), r);
        Log(buf);
        LeaveHook();
    }
    return r;
}


void InitWaitHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll  = GetModuleHandleA("ntdll.dll");
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
    if (!hKernel || !hNtdll || !hUser32) {
        Log("InitWaitHooks: kernel32/ntdll/user32 not loaded");
        return;
    }
    g_pNtQueryObject = (NtQueryObject_t)GetProcAddress(hNtdll, "NtQueryObject");
    if (!g_pNtQueryObject) Log("InitWaitHooks: NtQueryObject not found (names unavailable)");

    // NOTE: ntdll!NtWaitForSingleObject is DELIBERATELY NOT hooked.
    // Its prologue is a tiny syscall stub (mov eax,N / sysenter / ret 0xC)
    // that MinHook's HDE32 disassembler can't reliably trampoline. Hooking
    // it tore down Goley_ before InitWaitHooks finished. kernel32 wrappers
    // are enough to catch every long wait Goley_/nProtect does at user-mode.
    struct WaitHookSpec { HMODULE mod; const char* name; LPVOID detour; LPVOID* orig; };
    WaitHookSpec specs[] = {
        { hKernel, "WaitForSingleObject",    (LPVOID)&HookedWaitForSingleObject,   (LPVOID*)&g_origWFSO   },
        { hKernel, "WaitForSingleObjectEx",  (LPVOID)&HookedWaitForSingleObjectEx, (LPVOID*)&g_origWFSOEx },
        { hKernel, "WaitForMultipleObjects", (LPVOID)&HookedWaitForMultipleObjects,(LPVOID*)&g_origWFMO   },
        { hKernel, "WaitForMultipleObjectsEx", (LPVOID)&HookedWaitForMultipleObjectsEx,(LPVOID*)&g_origWFMOEx },
        { hUser32, "MsgWaitForMultipleObjects", (LPVOID)&HookedMsgWaitForMultipleObjects,(LPVOID*)&g_origMsgWFMO },
        { hUser32, "MsgWaitForMultipleObjectsEx", (LPVOID)&HookedMsgWaitForMultipleObjectsEx,(LPVOID*)&g_origMsgWFMOEx },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID p = GetProcAddress(specs[i].mod, specs[i].name);
        char buf[200];
        if (!p) {
            wsprintfA(buf, "InitWaitHooks: GetProcAddress(%s) FAILED", specs[i].name);
            Log(buf);
            continue;
        }
        MH_STATUS s = MH_CreateHook(p, specs[i].detour, specs[i].orig);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_CreateHook(%s) status=%d", specs[i].name, s);
            Log(buf);
            continue;
        }
        s = MH_EnableHook(p);
        if (s != MH_OK) {
            wsprintfA(buf, "InitWaitHooks: MH_EnableHook(%s) status=%d", specs[i].name, s);
            Log(buf);
            continue;
        }
        wsprintfA(buf, "InitWaitHooks: %s hooked at 0x%p", specs[i].name, p);
        Log(buf);
    }
}


