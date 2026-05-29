#include "hook_window.h"
#include "../core/logger.h"
#include "../core/helpers.h"

ATOM WINAPI HookedRegisterClassExA(const WNDCLASSEXA* lpwcx) {
    void* ret = _ReturnAddress();
    ATOM r = g_origRegisterClassExA(lpwcx);
    if (EnterHook()) {
        char modname[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule(ret, modname, sizeof(modname), &rva);
        char clsTxt[96] = {0};
        RenderClassNameA(lpwcx ? lpwcx->lpszClassName : NULL,
                         clsTxt, sizeof(clsTxt));
        char hInstTxt[80] = {0};
        RenderInstanceModule(lpwcx ? lpwcx->hInstance : NULL,
                             hInstTxt, sizeof(hInstTxt));
        char buf[400];
        wsprintfA(buf,
            "RegisterClassExA atom=0x%X class=%s hInst=%s style=0x%X "
            "wndProc=0x%p caller=%s+0x%X",
            r, clsTxt, hInstTxt,
            lpwcx ? lpwcx->style : 0,
            lpwcx ? (void*)lpwcx->lpfnWndProc : NULL,
            modname, rva);
        Log(buf);
        LeaveHook();
    }
    return r;
}


ATOM WINAPI HookedRegisterClassExW(const WNDCLASSEXW* lpwcx) {
    void* ret = _ReturnAddress();
    ATOM r = g_origRegisterClassExW(lpwcx);
    if (EnterHook()) {
        char modname[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule(ret, modname, sizeof(modname), &rva);
        char clsTxt[96] = {0};
        RenderClassNameW(lpwcx ? lpwcx->lpszClassName : NULL,
                         clsTxt, sizeof(clsTxt));
        char hInstTxt[80] = {0};
        RenderInstanceModule(lpwcx ? lpwcx->hInstance : NULL,
                             hInstTxt, sizeof(hInstTxt));
        char buf[400];
        wsprintfA(buf,
            "RegisterClassExW atom=0x%X class=%s hInst=%s style=0x%X "
            "wndProc=0x%p caller=%s+0x%X",
            r, clsTxt, hInstTxt,
            lpwcx ? lpwcx->style : 0,
            lpwcx ? (void*)lpwcx->lpfnWndProc : NULL,
            modname, rva);
        Log(buf);
        LeaveHook();
    }
    return r;
}


HWND WINAPI HookedCreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName,
                                          LPCSTR lpWindowName, DWORD dwStyle,
                                          int X, int Y, int nWidth, int nHeight,
                                          HWND hWndParent, HMENU hMenu,
                                          HINSTANCE hInstance, LPVOID lpParam) {
    void* ret = _ReturnAddress();
    HWND r = g_origCreateWindowExA(dwExStyle, lpClassName, lpWindowName,
                                    dwStyle, X, Y, nWidth, nHeight,
                                    hWndParent, hMenu, hInstance, lpParam);
    if (EnterHook()) {
        char modname[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule(ret, modname, sizeof(modname), &rva);
        char clsTxt[96];   RenderClassNameA(lpClassName, clsTxt, sizeof(clsTxt));
        char ttlTxt[120] = "<null>";
        if (lpWindowName) {
            char tmp[100] = {0};
            for (int i = 0; i < 99; i++) {
                char c = lpWindowName[i]; if (c == 0) break;
                tmp[i] = (c >= 32 && c < 127) ? c : '?';
            }
            wsprintfA(ttlTxt, "'%s'", tmp);
        }
        LogCreateResult(r, "CreateWindowExA", clsTxt, ttlTxt,
                        X, Y, nWidth, nHeight,
                        dwStyle, dwExStyle, modname, rva);
        LeaveHook();
    }
    return r;
}


HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
                                          LPCWSTR lpWindowName, DWORD dwStyle,
                                          int X, int Y, int nWidth, int nHeight,
                                          HWND hWndParent, HMENU hMenu,
                                          HINSTANCE hInstance, LPVOID lpParam) {
    void* ret = _ReturnAddress();
    HWND r = g_origCreateWindowExW(dwExStyle, lpClassName, lpWindowName,
                                    dwStyle, X, Y, nWidth, nHeight,
                                    hWndParent, hMenu, hInstance, lpParam);
    if (EnterHook()) {
        char modname[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule(ret, modname, sizeof(modname), &rva);
        char clsTxt[96];   RenderClassNameW(lpClassName, clsTxt, sizeof(clsTxt));
        char ttlTxt[120] = "<null>";
        if (lpWindowName) {
            char asc[100] = {0};
            WideCharToMultiByte(CP_ACP, 0, lpWindowName, -1,
                                asc, sizeof(asc) - 1, NULL, NULL);
            for (int i = 0; asc[i] && i < 99; i++) {
                if (asc[i] < 32 || asc[i] >= 127) asc[i] = '?';
            }
            wsprintfA(ttlTxt, "'%s'", asc);
        }
        LogCreateResult(r, "CreateWindowExW", clsTxt, ttlTxt,
                        X, Y, nWidth, nHeight,
                        dwStyle, dwExStyle, modname, rva);
        LeaveHook();
    }
    return r;
}


BOOL InitWindowAuditHooks() {
    HMODULE hUser = GetModuleHandleA("user32.dll");
    if (!hUser) return FALSE;
    PVOID pCWA = GetProcAddress(hUser, "CreateWindowExA");
    PVOID pCWW = GetProcAddress(hUser, "CreateWindowExW");
    PVOID pRCA = GetProcAddress(hUser, "RegisterClassExA");
    PVOID pRCW = GetProcAddress(hUser, "RegisterClassExW");
    char buf[300];
    wsprintfA(buf,
        "WinAudit targets: CWExA=0x%p CWExW=0x%p RCExA=0x%p RCExW=0x%p",
        pCWA, pCWW, pRCA, pRCW);
    Log(buf);
    BOOL anyOk = FALSE;
    if (pCWA) {
        MH_STATUS s = MH_CreateHook(pCWA, (LPVOID)&HookedCreateWindowExA,
                                    (LPVOID*)&g_origCreateWindowExA);
        if (s == MH_OK && MH_EnableHook(pCWA) == MH_OK) {
            Log("CreateWindowExA audit hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "CreateWindowExA audit hook FAILED status=%d", s); Log(buf);
        }
    }
    if (pCWW) {
        MH_STATUS s = MH_CreateHook(pCWW, (LPVOID)&HookedCreateWindowExW,
                                    (LPVOID*)&g_origCreateWindowExW);
        if (s == MH_OK && MH_EnableHook(pCWW) == MH_OK) {
            Log("CreateWindowExW audit hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "CreateWindowExW audit hook FAILED status=%d", s); Log(buf);
        }
    }
    if (pRCA) {
        MH_STATUS s = MH_CreateHook(pRCA, (LPVOID)&HookedRegisterClassExA,
                                    (LPVOID*)&g_origRegisterClassExA);
        if (s == MH_OK && MH_EnableHook(pRCA) == MH_OK) {
            Log("RegisterClassExA audit hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "RegisterClassExA audit hook FAILED status=%d", s); Log(buf);
        }
    }
    if (pRCW) {
        MH_STATUS s = MH_CreateHook(pRCW, (LPVOID)&HookedRegisterClassExW,
                                    (LPVOID*)&g_origRegisterClassExW);
        if (s == MH_OK && MH_EnableHook(pRCW) == MH_OK) {
            Log("RegisterClassExW audit hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "RegisterClassExW audit hook FAILED status=%d", s); Log(buf);
        }
    }
    return anyOk;
}


