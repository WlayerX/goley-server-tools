#include "syscalls.h"
#include "../core/logger.h"

typedef LONG (NTAPI *NtQip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static DWORD   g_ssnNtQip   = 0xFFFFFFFF;
static NtQip_t g_directNtQip = NULL;   // -> executable gadget
static NtQip_t g_liveNtQip   = NULL;   // -> live ntdll stub (may be hooked)

DWORD ResolveSyscallNumber(const char* ntFuncName) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) return 0xFFFFFFFF;
    BYTE* p = (BYTE*)GetProcAddress(hNt, ntFuncName);
    if (!p) return 0xFFFFFFFF;
    // Canonical x86 stub prologue: B8 <imm32>  (mov eax, ssn)
    if (p[0] != 0xB8) return 0xFFFFFFFF;
    return *(DWORD*)(p + 1);
}

BOOL InitDirectSyscalls(void) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) { Log("InitDirectSyscalls: ntdll not loaded"); return FALSE; }

    BYTE* p = (BYTE*)GetProcAddress(hNt, "NtQueryInformationProcess");
    g_liveNtQip = (NtQip_t)p;
    char buf[256];

    if (!p || p[0] != 0xB8) {
        wsprintfA(buf, "InitDirectSyscalls: stub not clean (p=0x%p first=0x%02X) -- gadget skipped, will use live stub",
                  p, p ? p[0] : 0);
        Log(buf);
        return FALSE;
    }

    g_ssnNtQip = *(DWORD*)(p + 1);
    BYTE* tail = p + 5;   // first byte after `mov eax, imm32` = real WOW64 transition

    // Gadget: B8 <ssn>  E9 <rel32 -> tail>      (10 bytes)
    BYTE* g = (BYTE*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g) {
        wsprintfA(buf, "InitDirectSyscalls: VirtualAlloc gadget FAILED err=%lu (using live stub)", GetLastError());
        Log(buf);
        return FALSE;
    }
    g[0] = 0xB8;
    *(DWORD*)(g + 1) = g_ssnNtQip;                 // mov eax, ssn
    g[5] = 0xE9;
    *(DWORD*)(g + 6) = (DWORD)(tail - (g + 10));    // jmp tail (rel32 from end of jmp)
    g_directNtQip = (NtQip_t)g;

    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    wsprintfA(buf, "InitDirectSyscalls: SSN(NtQueryInformationProcess)=0x%X gadget@0x%p tail@0x%p wow64=%d",
              g_ssnNtQip, g, tail, isWow64);
    Log(buf);
    return TRUE;
}

LONG DirectNtQueryInformationProcess(HANDLE h, ULONG cls, PVOID info, ULONG len, PULONG retLen) {
    NtQip_t fn = g_directNtQip ? g_directNtQip : g_liveNtQip;
    if (!fn) return (LONG)0xC0000001 /* STATUS_UNSUCCESSFUL */;
    return fn(h, cls, info, len, retLen);
}

void CompareNtQipHookedVsReal(HANDLE hProc, const char* tag) {
    // ProcessBasicInformation (class 0): ExitStatus is the first field (offset 0).
    // Query via the live (hooked) stub and via the direct gadget; compare.
    BYTE hooked[48] = {0};
    BYTE real[48]   = {0};
    ULONG rl1 = 0, rl2 = 0;

    LONG s1 = g_liveNtQip   ? g_liveNtQip(hProc, 0, hooked, sizeof(hooked), &rl1)
                            : (LONG)0xC0000001;
    LONG s2 = DirectNtQueryInformationProcess(hProc, 0, real, sizeof(real), &rl2);

    DWORD exitHooked = *(DWORD*)hooked;   // ExitStatus @ offset 0
    DWORD exitReal   = *(DWORD*)real;

    char buf[320];
    wsprintfA(buf, "[NtQIP-cmp %s] hProc=0x%p  hooked: status=0x%X ExitStatus=0x%X | real: status=0x%X ExitStatus=0x%X%s",
              tag, hProc, s1, exitHooked, s2, exitReal,
              (exitHooked != exitReal) ? "  *** DIVERGENCE ***" : "");
    Log(buf);
}
