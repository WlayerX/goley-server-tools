#include "hook_exit.h"
#include "../core/logger.h"
#include "../core/helpers.h"
#include "../core/memory.h"

// Trampolines to the real ntdll stubs (filled by MinHook).
typedef LONG (NTAPI *NtTerminateProcess_t)(HANDLE, LONG);
typedef VOID (NTAPI *RtlExitUserProcess_t)(UINT);
static NtTerminateProcess_t g_origNtTermProc = NULL;
static RtlExitUserProcess_t g_origRtlExit    = NULL;

// ----------------------------------------------------------------------------
// Caller stack walk: from the address of OUR return address, scan dwords
// upward and symbolicate code-like values. This recovers the Goley_/Themida
// call chain that requested the exit -- the whole point of these hooks.
// Guarded read in case the stack is mid-teardown.
// ----------------------------------------------------------------------------
static void LogCallerStack(const char* api) {
    DWORD* sp = (DWORD*)_AddressOfReturnAddress();
    char buf[400];
    wsprintfA(buf, "  [%s] caller stack walk:", api);
    LogCrash(buf);
    int shown = 0;
    for (int i = 0; i < 48 && shown < 16; i++) {
        DWORD val = 0;
        __try {
            val = *(volatile DWORD*)(sp + i);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        char m[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule((void*)val, m, sizeof(m), &rva);
        if (lstrcmpA(m, "<anon>") != 0) {
            wsprintfA(buf, "    ret[+0x%02X]=0x%08X  %s+0x%X (%s)",
                      i * 4, val, m, rva, ClassifyEip(val));
            LogCrash(buf);
            shown++;
        }
    }
}

LONG NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, LONG ExitStatus) {
    DWORD caller = (DWORD)(ULONG_PTR)_ReturnAddress();
    char cm[64] = {0}; DWORD crva = 0;
    ResolveAddrToModule((void*)caller, cm, sizeof(cm), &crva);

    char buf[256];
    wsprintfA(buf, "*** ntdll!NtTerminateProcess(h=0x%p, status=0x%X) caller=0x%X (%s+0x%X) ***",
              ProcessHandle, ExitStatus, caller, cm, crva);
    Log(buf);
    LogCrash(buf);
    LogCallerStack("NtTerminateProcess");

    // Self-termination? (NULL or pseudo-handle -1 == current process). Block by
    // spinning so we keep the process alive for inspection. External target ->
    // pass through to the real stub.
    BOOL self = (ProcessHandle == NULL ||
                 ProcessHandle == GetCurrentProcess() ||
                 (DWORD)(ULONG_PTR)ProcessHandle == (DWORD)-1);
    if (self) {
        LogCrash("  -> SELF terminate BLOCKED (spinning)");
        while (1) { Sleep(60000); }
    }
    return g_origNtTermProc ? g_origNtTermProc(ProcessHandle, ExitStatus)
                            : (LONG)0xC0000001 /* STATUS_UNSUCCESSFUL */;
}

VOID NTAPI HookedRtlExitUserProcess(UINT uExitCode) {
    DWORD caller = (DWORD)(ULONG_PTR)_ReturnAddress();
    char cm[64] = {0}; DWORD crva = 0;
    ResolveAddrToModule((void*)caller, cm, sizeof(cm), &crva);

    char buf[256];
    wsprintfA(buf, "*** ntdll!RtlExitUserProcess(code=0x%X) caller=0x%X (%s+0x%X) -- BLOCKED (spinning) ***",
              uExitCode, caller, cm, crva);
    Log(buf);
    LogCrash(buf);
    LogCallerStack("RtlExitUserProcess");

    // RtlExitUserProcess is the normal-exit funnel and is __declspec(noreturn);
    // always block (spin) -- we never want a clean self-exit during bypass.
    while (1) { Sleep(60000); }
}

int InitExitHooks(void) {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        char buf[128];
        wsprintfA(buf, "InitExitHooks: MH_Initialize FAILED status=%d", s);
        Log(buf);
        return 0;
    }

    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) { Log("InitExitHooks: ntdll not loaded"); return 0; }

    struct Spec { const char* name; LPVOID detour; LPVOID* orig; };
    Spec specs[] = {
        { "NtTerminateProcess", (LPVOID)&HookedNtTerminateProcess, (LPVOID*)&g_origNtTermProc },
        { "RtlExitUserProcess", (LPVOID)&HookedRtlExitUserProcess, (LPVOID*)&g_origRtlExit    },
    };

    int hooked = 0;
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        PVOID p = GetProcAddress(hNt, specs[i].name);
        char buf[256];
        if (!p) {
            wsprintfA(buf, "InitExitHooks: GetProcAddress(%s) FAILED", specs[i].name);
            Log(buf);
            continue;
        }
        s = MH_CreateHook(p, specs[i].detour, specs[i].orig);
        if (s == MH_OK) s = MH_EnableHook(p);
        if (s == MH_OK) {
            wsprintfA(buf, "InitExitHooks: %s hooked via MinHook at 0x%p", specs[i].name, p);
            Log(buf);
            hooked++;
        } else {
            // Short ntdll syscall stubs can defeat HDE32 trampolining (same
            // reason NtWaitForSingleObject is left unhooked). Preserve the
            // "don't die" guarantee with the legacy EB-FE hang-stub fallback,
            // and say so clearly in the log.
            wsprintfA(buf, "InitExitHooks: MinHook(%s) status=%d -> falling back to PatchHangStub",
                      specs[i].name, s);
            Log(buf);
            PatchHangStub((DWORD)(ULONG_PTR)p, specs[i].name);
        }
    }
    return hooked;
}
