#include "helpers.h"
#include "logger.h"

// ============================================================================
// Hook recursion guard
// ============================================================================
BOOL EnterHook(void) {
    return InterlockedCompareExchange(&g_inHook, 1, 0) == 0;
}

void LeaveHook(void) {
    InterlockedExchange(&g_inHook, 0);
}

// ============================================================================
// EIP classification for thread dump
// ============================================================================
const char* ClassifyEip(DWORD eip) {
    static char buf[64];
    HMODULE hKernel  = GetModuleHandleA("kernel32.dll");
    HMODULE hKernelB = GetModuleHandleA("kernelbase.dll");
    HMODULE hNtdll   = GetModuleHandleA("ntdll.dll");
    HMODULE hUser32  = GetModuleHandleA("user32.dll");
    HMODULE hWs2     = GetModuleHandleA("ws2_32.dll");
    HMODULE hImage   = GetModuleHandleA(NULL);

    struct { HMODULE h; const char* tag; DWORD size; } mods[] = {
        { hImage,   "image",      0x02000000 },
        { hNtdll,   "ntdll",      0x00200000 },
        { hKernel,  "kernel32",   0x00200000 },
        { hKernelB, "kernelbase", 0x00400000 },
        { hUser32,  "user32",     0x00200000 },
        { hWs2,     "ws2_32",     0x00100000 },
    };
    for (int i = 0; i < (int)(sizeof(mods)/sizeof(mods[0])); i++) {
        if (!mods[i].h) continue;
        DWORD base = (DWORD)(ULONG_PTR)mods[i].h;
        if (eip >= base && eip < base + mods[i].size) {
            wsprintfA(buf, "%s+0x%X", mods[i].tag, eip - base);
            return buf;
        }
    }
    wsprintfA(buf, "?(0x%X)", eip);
    return buf;
}

// ============================================================================
// Handle name resolution via NtQueryObject
// ============================================================================
void DescribeHandle(HANDLE h, char* buf, int bufSize) {
    if (!g_pNtQueryObject || bufSize < 4) {
        if (bufSize >= 4) lstrcpyA(buf, "?");
        return;
    }
    BYTE tmp[1024] = {0};
    ULONG retLen = 0;
    LONG status = g_pNtQueryObject(h, 1 /*ObjectNameInformation*/,
                                   tmp, sizeof(tmp), &retLen);
    if (status < 0) {
        wsprintfA(buf, "name?(0x%lX)", status);
        return;
    }
    OBJECT_NAME_INFORMATION_local* info = (OBJECT_NAME_INFORMATION_local*)tmp;
    if (info->Name.Length == 0 || info->Name.Buffer == NULL) {
        lstrcpyA(buf, "<unnamed>");
        return;
    }
    int chars = info->Name.Length / (int)sizeof(wchar_t);
    if (chars > bufSize - 4) chars = bufSize - 4;
    for (int i = 0; i < chars; i++) {
        wchar_t c = info->Name.Buffer[i];
        buf[i] = (c >= 0x20 && c < 0x80) ? (char)c : '?';
    }
    buf[chars] = 0;
}

// ============================================================================
// Module/address resolution
// ============================================================================
void ResolveAddrToModule(void* addr, char* outName, int outLen, DWORD* rvaOut) {
    HMODULE hMod = NULL;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &hMod) && hMod) {
        char path[MAX_PATH] = {0};
        if (GetModuleFileNameA(hMod, path, MAX_PATH)) {
            const char* base = strrchr(path, '\\');
            base = base ? base + 1 : path;
            lstrcpynA(outName, base, outLen);
        } else {
            lstrcpynA(outName, "<unnamed>", outLen);
        }
        if (rvaOut) *rvaOut = (DWORD)((ULONG_PTR)addr - (ULONG_PTR)hMod);
    } else {
        lstrcpynA(outName, "<anon>", outLen);
        if (rvaOut) *rvaOut = 0;
    }
}

// ============================================================================
// Class name rendering for logs
// ============================================================================
void RenderClassNameA(LPCSTR cls, char* out, int outLen) {
    if (!cls) { lstrcpynA(out, "<null>", outLen); return; }
    if (((ULONG_PTR)cls) >> 16 == 0) {
        wsprintfA(out, "ATOM(0x%X)", (unsigned)(ULONG_PTR)cls);
    } else {
        char tmp[80] = {0};
        for (int i = 0; i < 79; i++) {
            char c = cls[i];
            if (c == 0) break;
            tmp[i] = (c >= 32 && c < 127) ? c : '?';
        }
        wsprintfA(out, "'%s'", tmp);
    }
}

void RenderClassNameW(LPCWSTR cls, char* out, int outLen) {
    if (!cls) { lstrcpynA(out, "<null>", outLen); return; }
    if (((ULONG_PTR)cls) >> 16 == 0) {
        wsprintfA(out, "ATOM(0x%X)", (unsigned)(ULONG_PTR)cls);
    } else {
        char asc[80] = {0};
        int n = WideCharToMultiByte(CP_ACP, 0, cls, -1,
                                    asc, sizeof(asc) - 1, NULL, NULL);
        (void)n;
        for (int i = 0; asc[i] && i < 79; i++) {
            if (asc[i] < 32 || asc[i] >= 127) asc[i] = '?';
        }
        wsprintfA(out, "'%s'", asc);
    }
}

void RenderInstanceModule(HINSTANCE hInst, char* out, int outLen) {
    if (!hInst) { lstrcpynA(out, "<exe>", outLen); return; }
    char path[MAX_PATH] = {0};
    if (GetModuleFileNameA((HMODULE)hInst, path, MAX_PATH)) {
        const char* base = strrchr(path, '\\');
        base = base ? base + 1 : path;
        lstrcpynA(out, base, outLen);
    } else {
        wsprintfA(out, "<?>=0x%p", hInst);
    }
}

void LogCreateResult(HWND hwnd, const char* api,
                    const char* clsTxt, const char* titleTxt,
                    int reqX, int reqY, int reqW, int reqH,
                    DWORD style, DWORD exStyle,
                    const char* callerMod, DWORD callerRva) {
    RECT r = {0};
    if (hwnd) GetWindowRect(hwnd, &r);
    int finalW = r.right - r.left;
    int finalH = r.bottom - r.top;

    HMODULE clsMod = NULL;
    char clsModName[64] = "<?>";
    if (hwnd) {
        clsMod = (HMODULE)GetClassLongPtrA(hwnd, GCLP_HMODULE);
        if (clsMod) {
            char path[MAX_PATH] = {0};
            if (GetModuleFileNameA(clsMod, path, MAX_PATH)) {
                const char* base = strrchr(path, '\\');
                base = base ? base + 1 : path;
                lstrcpynA(clsModName, base, sizeof(clsModName));
            }
        } else {
            lstrcpynA(clsModName, "<anon>", sizeof(clsModName));
        }
    }

    DWORD tid = hwnd ? GetWindowThreadProcessId(hwnd, NULL) : 0;

    char buf[600];
    wsprintfA(buf,
        "%s hwnd=0x%p class=%s title=%s req=%dx%d final=%dx%d "
        "style=0x%X exStyle=0x%X tid=%lu classMod=%s caller=%s+0x%X",
        api, hwnd, clsTxt, titleTxt,
        reqW, reqH, finalW, finalH,
        style, exStyle, tid, clsModName,
        callerMod, callerRva);
    Log(buf);

    if ((finalW == 371 && finalH == 143) ||
        (reqW   == 371 && reqH   == 143)) {
        char buf2[700];
        wsprintfA(buf2,
            "*** SUSPECT DIALOG MATCH 371x143 *** api=%s class=%s "
            "classMod=%s caller=%s+0x%X title=%s",
            api, clsTxt, clsModName, callerMod, callerRva, titleTxt);
        Log(buf2);
    }
}

// ============================================================================
// Path basename extraction
// ============================================================================
void GetBasenameA(const char* path, char* outBase, int outLen) {
    outBase[0] = 0;
    if (!path) return;
    const char* base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    lstrcpynA(outBase, base, outLen);
}

void GetBasenameW(LPCWSTR path, char* outBase, int outLen) {
    outBase[0] = 0;
    if (!path) return;
    char asc[280] = {0};
    for (int i = 0; i < 279 && path[i]; i++)
        asc[i] = (path[i] < 0x80) ? (char)path[i] : '?';
    GetBasenameA(asc, outBase, outLen);
}

void ResolveChildBasenameA(const char* lpApp, const char* lpCmd,
                           char* outBase, int outLen) {
    if (lpApp) { GetBasenameA(lpApp, outBase, outLen); return; }
    if (!lpCmd) { outBase[0] = 0; return; }
    char tmp[280] = {0};
    const char* p = lpCmd;
    while (*p == ' ' || *p == '\t') p++;
    bool quoted = (*p == '"');
    if (quoted) p++;
    int i = 0;
    while (*p && i < 279) {
        if (quoted && *p == '"') break;
        if (!quoted && (*p == ' ' || *p == '\t')) break;
        tmp[i++] = *p++;
    }
    GetBasenameA(tmp, outBase, outLen);
}

void ResolveChildBasenameW(LPCWSTR lpApp, LPCWSTR lpCmd,
                           char* outBase, int outLen) {
    if (lpApp) { GetBasenameW(lpApp, outBase, outLen); return; }
    if (!lpCmd) { outBase[0] = 0; return; }
    char ascCmd[280] = {0};
    for (int i = 0; i < 279 && lpCmd[i]; i++)
        ascCmd[i] = (lpCmd[i] < 0x80) ? (char)lpCmd[i] : '?';
    ResolveChildBasenameA(NULL, ascCmd, outBase, outLen);
}
