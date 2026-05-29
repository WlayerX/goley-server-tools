#include "hook_ipc.h"
#include "../core/logger.h"
#include "../core/helpers.h"

static CreateFileMappingA_t g_origCFMA = NULL;
static CreateFileMappingW_t g_origCFMW = NULL;
static OpenFileMappingA_t   g_origOFMA = NULL;
static OpenFileMappingW_t   g_origOFMW = NULL;
static MapViewOfFile_t      g_origMVF  = NULL;
static MapViewOfFileEx_t    g_origMVFEx = NULL;
static DeviceIoControl_t    g_origDIOC = NULL;

// Shared helper: caller module+RVA into a small buffer.
static void CallerStr(void* ret, char* out, int outLen) {
    char m[64] = {0}; DWORD rva = 0;
    ResolveAddrToModule(ret, m, sizeof(m), &rva);
    wsprintfA(out, "%s+0x%X", m, rva);
}

HANDLE WINAPI HookedCreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES sa,
                                       DWORD prot, DWORD szHi, DWORD szLo, LPCSTR name) {
    void* ret = _ReturnAddress();
    HANDLE h = g_origCFMA(hFile, sa, prot, szHi, szLo, name);
    if (EnterHook()) {
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[400];
        wsprintfA(buf, "[IPC] CreateFileMappingA name='%s' size=0x%X:%X prot=0x%X hFile=0x%p -> h=0x%p caller=%s",
                  name ? name : "<anon>", szHi, szLo, prot, hFile, h, cs);
        Log(buf);
        LeaveHook();
    }
    return h;
}

HANDLE WINAPI HookedCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES sa,
                                       DWORD prot, DWORD szHi, DWORD szLo, LPCWSTR name) {
    void* ret = _ReturnAddress();
    HANDLE h = g_origCFMW(hFile, sa, prot, szHi, szLo, name);
    if (EnterHook()) {
        char nameA[200] = "<anon>";
        if (name) {
            int i = 0;
            for (; i < 199 && name[i]; i++) nameA[i] = (name[i] < 0x80) ? (char)name[i] : '?';
            nameA[i] = 0;
        }
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[440];
        wsprintfA(buf, "[IPC] CreateFileMappingW name='%s' size=0x%X:%X prot=0x%X hFile=0x%p -> h=0x%p caller=%s",
                  nameA, szHi, szLo, prot, hFile, h, cs);
        Log(buf);
        LeaveHook();
    }
    return h;
}

HANDLE WINAPI HookedOpenFileMappingA(DWORD access, BOOL inherit, LPCSTR name) {
    void* ret = _ReturnAddress();
    HANDLE h = g_origOFMA(access, inherit, name);
    if (EnterHook()) {
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[400];
        wsprintfA(buf, "[IPC] OpenFileMappingA name='%s' access=0x%X -> h=0x%p caller=%s",
                  name ? name : "<null>", access, h, cs);
        Log(buf);
        LeaveHook();
    }
    return h;
}

HANDLE WINAPI HookedOpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name) {
    void* ret = _ReturnAddress();
    HANDLE h = g_origOFMW(access, inherit, name);
    if (EnterHook()) {
        char nameA[200] = "<null>";
        if (name) {
            int i = 0;
            for (; i < 199 && name[i]; i++) nameA[i] = (name[i] < 0x80) ? (char)name[i] : '?';
            nameA[i] = 0;
        }
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[440];
        wsprintfA(buf, "[IPC] OpenFileMappingW name='%s' access=0x%X -> h=0x%p caller=%s",
                  nameA, access, h, cs);
        Log(buf);
        LeaveHook();
    }
    return h;
}

LPVOID WINAPI HookedMapViewOfFile(HANDLE hMap, DWORD access, DWORD offHi, DWORD offLo, SIZE_T bytes) {
    void* ret = _ReturnAddress();
    LPVOID p = g_origMVF(hMap, access, offHi, offLo, bytes);
    if (EnterHook()) {
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[300];
        wsprintfA(buf, "[IPC] MapViewOfFile hMap=0x%p access=0x%X off=0x%X:%X bytes=0x%X -> 0x%p caller=%s",
                  hMap, access, offHi, offLo, (DWORD)bytes, p, cs);
        Log(buf);
        LeaveHook();
    }
    return p;
}

LPVOID WINAPI HookedMapViewOfFileEx(HANDLE hMap, DWORD access, DWORD offHi, DWORD offLo, SIZE_T bytes, LPVOID base) {
    void* ret = _ReturnAddress();
    LPVOID p = g_origMVFEx(hMap, access, offHi, offLo, bytes, base);
    if (EnterHook()) {
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[320];
        wsprintfA(buf, "[IPC] MapViewOfFileEx hMap=0x%p access=0x%X off=0x%X:%X bytes=0x%X base=0x%p -> 0x%p caller=%s",
                  hMap, access, offHi, offLo, (DWORD)bytes, base, p, cs);
        Log(buf);
        LeaveHook();
    }
    return p;
}

BOOL WINAPI HookedDeviceIoControl(HANDLE hDev, DWORD ioctl, LPVOID inBuf, DWORD inSize,
                                  LPVOID outBuf, DWORD outSize, LPDWORD bytesRet, LPOVERLAPPED ov) {
    void* ret = _ReturnAddress();
    BOOL ok = g_origDIOC(hDev, ioctl, inBuf, inSize, outBuf, outSize, bytesRet, ov);
    if (EnterHook()) {
        // IOCTL decode: device type (bits 16-31), function (bits 2-13).
        DWORD devType = (ioctl >> 16) & 0xFFFF;
        DWORD func    = (ioctl >> 2) & 0xFFF;
        char cs[96]; CallerStr(ret, cs, sizeof(cs));
        char buf[360];
        wsprintfA(buf, "[IPC] DeviceIoControl hDev=0x%p ioctl=0x%08X (devType=0x%X func=0x%X) inSz=%lu outSz=%lu -> %d caller=%s",
                  hDev, ioctl, devType, func, inSize, outSize, ok, cs);
        Log(buf);
        LeaveHook();
    }
    return ok;
}

BOOL InitIpcHooks(void) {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        char buf[96];
        wsprintfA(buf, "InitIpcHooks: MH_Initialize FAILED status=%d", s);
        Log(buf);
        return FALSE;
    }
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) { Log("InitIpcHooks: kernel32 not loaded"); return FALSE; }

    struct Spec { const char* name; LPVOID detour; LPVOID* orig; };
    Spec specs[] = {
        { "CreateFileMappingA", (LPVOID)&HookedCreateFileMappingA, (LPVOID*)&g_origCFMA },
        { "CreateFileMappingW", (LPVOID)&HookedCreateFileMappingW, (LPVOID*)&g_origCFMW },
        { "OpenFileMappingA",   (LPVOID)&HookedOpenFileMappingA,   (LPVOID*)&g_origOFMA },
        { "OpenFileMappingW",   (LPVOID)&HookedOpenFileMappingW,   (LPVOID*)&g_origOFMW },
        { "MapViewOfFile",      (LPVOID)&HookedMapViewOfFile,      (LPVOID*)&g_origMVF  },
        { "MapViewOfFileEx",    (LPVOID)&HookedMapViewOfFileEx,    (LPVOID*)&g_origMVFEx },
        { "DeviceIoControl",    (LPVOID)&HookedDeviceIoControl,    (LPVOID*)&g_origDIOC },
    };

    int n = 0;
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID p = GetProcAddress(hKernel, specs[i].name);
        char buf[200];
        if (!p) {
            wsprintfA(buf, "InitIpcHooks: GetProcAddress(%s) FAILED", specs[i].name);
            Log(buf);
            continue;
        }
        s = MH_CreateHook(p, specs[i].detour, specs[i].orig);
        if (s == MH_OK) s = MH_EnableHook(p);
        if (s == MH_OK) { n++; }
        else {
            wsprintfA(buf, "InitIpcHooks: hook(%s) status=%d", specs[i].name, s);
            Log(buf);
        }
    }
    char buf[120];
    wsprintfA(buf, "InitIpcHooks: %d/7 IPC observer hook(s) ACTIVE", n);
    Log(buf);
    return n > 0;
}
