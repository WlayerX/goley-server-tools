#include "hook_wait.h"
#include "../core/logger.h"
#include "../core/helpers.h"

DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout) {
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && EnterHook()) {
        char name[300];
        DescribeHandle(hObj, name, sizeof(name));
        char buf[600];
        wsprintfA(buf, "[WFSO] TID=%lu h=0x%p timeout=%lu name='%s' caller=0x%p",
                  GetCurrentThreadId(), hObj, dwTimeout, name, _ReturnAddress());
        Log(buf);

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
            wsprintfA(buf, "  *** nProtect EVENT DETECTED: '%s' -- auto-signaling ***", name);
            Log(buf);
            SetEvent(hObj);
        }
        // Isimsiz handle + INFINITE timeout: nProtect anonim event
        // kullanabilir. Ilk 90 sn icinde 100ms poll ile dene, sonra
        // orijinal INFINITE'e birak.
        else if (dwTimeout == INFINITE && lstrcmpA(name, "<unnamed>") == 0) {
            static volatile LONG g_anonWaitCount = 0;
            LONG anonIdx = InterlockedIncrement(&g_anonWaitCount);
            if (anonIdx <= 20) {
                wsprintfA(buf, "  anon-INFINITE wait #%ld -- polling 100ms x 900", anonIdx);
                Log(buf);
                LeaveHook();
                // 90 sn boyunca 100ms aralikla poll
                for (int attempt = 0; attempt < 900; attempt++) {
                    DWORD r = g_origWFSO(hObj, 100);
                    if (r == WAIT_OBJECT_0) {
                        if (EnterHook()) {
                            wsprintfA(buf, "  anon wait #%ld signaled after %d ms",
                                      anonIdx, (attempt + 1) * 100);
                            Log(buf);
                            LeaveHook();
                        }
                        return r;
                    }
                }
                // 90 sn doldu, orijinal INFINITE'e birak
                if (EnterHook()) {
                    wsprintfA(buf, "  anon wait #%ld: 90s poll exhausted, trying SetEvent",
                              anonIdx);
                    Log(buf);
                    // Son care: event'i kendimiz signal edelim
                    SetEvent(hObj);
                    LeaveHook();
                }
                DWORD r = g_origWFSO(hObj, 2000);
                return r;
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
    BOOL longWait = (dwTimeout == INFINITE) || (dwTimeout >= 1000);
    if (longWait && EnterHook()) {
        char name[300];
        DescribeHandle(hObj, name, sizeof(name));
        char buf[600];
        wsprintfA(buf, "[WFSOEx] TID=%lu h=0x%p timeout=%lu alertable=%d name='%s' caller=0x%p",
                  GetCurrentThreadId(), hObj, dwTimeout, bAlertable, name,
                  _ReturnAddress());
        Log(buf);

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
            wsprintfA(buf, "  *** nProtect EVENT (Ex) DETECTED: '%s' -- auto-signaling ***", name);
            Log(buf);
            SetEvent(hObj);
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


void InitWaitHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll  = GetModuleHandleA("ntdll.dll");
    if (!hKernel || !hNtdll) {
        Log("InitWaitHooks: kernel32/ntdll not loaded");
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


