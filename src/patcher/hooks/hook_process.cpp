#include "hook_process.h"
#include "../core/logger.h"
#include "../core/helpers.h"

VOID WINAPI HookedExitProcess(UINT uExitCode) {
    DWORD retAddr = (DWORD)(ULONG_PTR)_ReturnAddress();
    char buf[256];
    wsprintfA(buf, "*** ExitProcess(0x%X) called from caller=0x%X -- SUSPENDING thread ***",
              uExitCode, retAddr);
    Log(buf);
    // Suspend forever -- gives us time to attach debugger / take screenshot
    while (1) { Sleep(60000); }
}


BOOL WINAPI HookedTerminateProcess(HANDLE hProc, UINT uExitCode) {
    DWORD retAddr = (DWORD)(ULONG_PTR)_ReturnAddress();
    char buf[256];
    wsprintfA(buf, "*** TerminateProcess(hProc=0x%p, code=0x%X) called from caller=0x%X -- BLOCKED ***",
              hProc, uExitCode, retAddr);
    Log(buf);
    // If target is OUR process, block it. If external, allow.
    if (hProc == GetCurrentProcess() || (DWORD)(ULONG_PTR)hProc == (DWORD)-1) {
        while (1) { Sleep(60000); }
    }
    return g_origTerminateProcess ? g_origTerminateProcess(hProc, uExitCode) : FALSE;
}

BOOL WINAPI HookedGetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
    BOOL ret = g_origGetExitCodeProcess(hProcess, lpExitCode);
    if (ret && lpExitCode) {
        if (*lpExitCode != STILL_ACTIVE) {
            char buf[256];
            wsprintfA(buf, "[HOOK] GetExitCodeProcess(hProc=0x%p) -> OVERRIDING error code 0x%X to 0 (Success)", hProcess, *lpExitCode);
            Log(buf);
            *lpExitCode = 0;
        }
    }
    return ret;
}

typedef LONG (NTAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NtQueryInformationProcess_t g_origNtQIP = NULL;

LONG NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    LONG status = g_origNtQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if (status >= 0 && ProcessInformationClass == 0 && ProcessInformation) {
        // ProcessBasicInformation -> ExitStatus is at offset 0
        PDWORD pExitStatus = (PDWORD)ProcessInformation;
        if (*pExitStatus != STILL_ACTIVE && *pExitStatus != 0) {
            char buf[256];
            wsprintfA(buf, "[HOOK] NtQueryInformationProcess(hProc=0x%p) -> OVERRIDING ExitStatus 0x%X to 0", ProcessHandle, *pExitStatus);
            Log(buf);
            *pExitStatus = 0;
        }
    }
    return status;
}


int HookKillApis() {
    int hooks = 0;
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 0;

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) return 0;

    FARPROC origExit  = GetProcAddress(hKernel, "ExitProcess");
    FARPROC origTerm  = GetProcAddress(hKernel, "TerminateProcess");
    g_origExitProcess      = (ExitProcess_t)origExit;
    g_origTerminateProcess = (TerminateProcess_t)origTerm;

    BYTE* base = (BYTE*)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD impDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impDirRva) return 0;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impDirRva);

    for (; imp->Name; imp++) {
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
        for (; iat->u1.Function; iat++) {
            FARPROC* slot = (FARPROC*)&iat->u1.Function;
            DWORD oldProt;
            if (*slot == origExit) {
                VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &oldProt);
                *slot = (FARPROC)HookedExitProcess;
                VirtualProtect(slot, sizeof(FARPROC), oldProt, &oldProt);
                Log("Hooked ExitProcess IAT slot");
                hooks++;
            } else if (*slot == origTerm) {
                VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &oldProt);
                *slot = (FARPROC)HookedTerminateProcess;
                VirtualProtect(slot, sizeof(FARPROC), oldProt, &oldProt);
                Log("Hooked TerminateProcess IAT slot");
                hooks++;
            }
        }
    }
    return hooks;
}


BOOL ApcInjectChild(HANDLE hProcess, HANDLE hThread, DWORD childPid) {
    SIZE_T pathLen = lstrlenA(SELF_DLL_PATH) + 1;
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        char buf[160];
        wsprintfA(buf, "  child[%lu] VirtualAllocEx FAILED err=%lu",
                  childPid, GetLastError());
        Log(buf);
        return FALSE;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemote, SELF_DLL_PATH, pathLen, &written)) {
        char buf[160];
        wsprintfA(buf, "  child[%lu] WriteProcessMemory FAILED err=%lu",
                  childPid, GetLastError());
        Log(buf);
        return FALSE;
    }
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    PVOID pLoadLib = GetProcAddress(hKernel, "LoadLibraryA");
    if (!pLoadLib) {
        Log("  ApcInjectChild: GetProcAddress(LoadLibraryA) FAILED");
        return FALSE;
    }
    DWORD r = QueueUserAPC((PAPCFUNC)pLoadLib, hThread, (ULONG_PTR)pRemote);
    char buf[256];
    wsprintfA(buf, "  child[%lu] APC queued at 0x%p (LoadLibraryA path 0x%p) -> %s",
              childPid, pLoadLib, pRemote, r ? "OK" : "FAIL");
    Log(buf);
    return r != 0;
}


BOOL WINAPI HookedCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char childBase[128] = {0};
    ResolveChildBasenameA(lpApplicationName, lpCommandLine,
                          childBase, sizeof(childBase));
    // Self-exec guard log-only: parent process basename child basename ile
    // ayni mi? (Goley_.exe -> Goley_.exe gibi infinite re-exec pattern)
    char selfExe[MAX_PATH] = {0};
    char selfBase[64] = {0};
    if (GetModuleFileNameA(NULL, selfExe, MAX_PATH) > 0) {
        const char* sb = strrchr(selfExe, '\\');
        sb = sb ? sb + 1 : selfExe;
        lstrcpynA(selfBase, sb, sizeof(selfBase));
    }
    bool isSelfExec = (childBase[0] && lstrcmpiA(childBase, selfBase) == 0);

    char buf[1024];
    if (isSelfExec) {
        wsprintfA(buf, "*** SELF-EXEC *** [HOOK] CreateProcessA: child='%s' (== parent) cmd='%.180s' flags=0x%X",
                  childBase, lpCommandLine ? lpCommandLine : "(null)", dwCreationFlags);
    } else {
        wsprintfA(buf, "[HOOK] CreateProcessA: child='%s' app='%s' cmd='%.180s' flags=0x%X cwd='%s'",
                  childBase,
                  lpApplicationName ? lpApplicationName : "(null)",
                  lpCommandLine     ? lpCommandLine     : "(null)",
                  dwCreationFlags,
                  lpCurrentDirectory ? lpCurrentDirectory : "(null)");
    }
    Log(buf);

    // OBSERVER MODE (LAUNCHER veya PAYLOAD): Bu hook SADECE gozlemci.
    //   * Flags DEGISMEZ (CREATE_SUSPENDED eklenmez)
    //   * APC inject YOK
    //   * Manuel ResumeThread YOK
    //   * Child basenamesi loglanir, return result loglanir.
    // Launcher icin: IFEO wrapper Goley_.exe spawn'inda inject'i halleder.
    // Payload icin: phase 1 minimal observer, child'a HIC dokunmaz.
    if (IS_OBSERVER_MODE()) {
        BOOL ok = g_origCreateProcessA(
            lpApplicationName, lpCommandLine,
            lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
        const char* tag = g_launcherMode ? "launcher" : "payload";
        if (ok && lpProcessInformation) {
            wsprintfA(buf, "  -> [%s observe-only] PID=%lu child='%s'",
                      tag, lpProcessInformation->dwProcessId, childBase);
            Log(buf);
        } else if (!ok) {
            wsprintfA(buf, "  -> [%s] CreateProcessA FAILED err=%lu", tag, GetLastError());
            Log(buf);
        }
        return ok;
    }

    // GAME MODE: mevcut agresif davranis (CREATE_SUSPENDED + APC inject).
    // Force CREATE_SUSPENDED so the child can't run before we APC-inject.
    BOOL addedSuspend = !(dwCreationFlags & CREATE_SUSPENDED);
    DWORD effectiveFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL ok = g_origCreateProcessA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, effectiveFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (!ok) {
        wsprintfA(buf, "  -> CreateProcessA FAILED err=%lu", GetLastError());
        Log(buf);
        return ok;
    }

    HANDLE hProcess = lpProcessInformation->hProcess;
    HANDLE hThread  = lpProcessInformation->hThread;
    DWORD  childPid = lpProcessInformation->dwProcessId;
    wsprintfA(buf, "  -> CHILD spawned PID=%lu hProc=0x%p hThread=0x%p addedSuspend=%d",
              childPid, hProcess, hThread, addedSuspend);
    Log(buf);

    if (lstrcmpiA(childBase, "GameGuard.des") == 0) {
        g_hGameMonProcess = hProcess;
    }

    ApcInjectChild(hProcess, hThread, childPid);

    // If WE added CREATE_SUSPENDED (caller didn't ask for it), we must
    // resume the thread ourselves so the caller's expectation holds.
    // The APC we queued will fire on the very first user-mode dispatch.
    if (addedSuspend) {
        DWORD prev = ResumeThread(hThread);
        wsprintfA(buf, "  -> manual ResumeThread (prev suspend count=%lu)", prev);
        Log(buf);
    }
    // Else: caller will resume the thread themselves -- APC still fires.
    return ok;
}


BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR  lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char childBase[128] = {0};
    ResolveChildBasenameW(lpApplicationName, lpCommandLine,
                          childBase, sizeof(childBase));
    // Self-exec guard log-only (same logic as A variant).
    char selfExeW[MAX_PATH] = {0};
    char selfBaseW[64] = {0};
    if (GetModuleFileNameA(NULL, selfExeW, MAX_PATH) > 0) {
        const char* sb = strrchr(selfExeW, '\\');
        sb = sb ? sb + 1 : selfExeW;
        lstrcpynA(selfBaseW, sb, sizeof(selfBaseW));
    }
    bool isSelfExecW = (childBase[0] && lstrcmpiA(childBase, selfBaseW) == 0);

    char buf[1024];
    char appA[260] = {0};
    char cmdA[260] = {0};
    char cwdA[260] = {0};
    if (lpApplicationName)
        for (int i = 0; i < 259 && lpApplicationName[i]; i++)
            appA[i] = (lpApplicationName[i] < 0x80) ? (char)lpApplicationName[i] : '?';
    if (lpCommandLine)
        for (int i = 0; i < 259 && lpCommandLine[i]; i++)
            cmdA[i] = (lpCommandLine[i] < 0x80) ? (char)lpCommandLine[i] : '?';
    if (lpCurrentDirectory)
        for (int i = 0; i < 259 && lpCurrentDirectory[i]; i++)
            cwdA[i] = (lpCurrentDirectory[i] < 0x80) ? (char)lpCurrentDirectory[i] : '?';
    if (isSelfExecW) {
        wsprintfA(buf, "*** SELF-EXEC *** [HOOK] CreateProcessW: child='%s' (== parent) cmd='%s' flags=0x%X",
                  childBase, cmdA, dwCreationFlags);
    } else {
        wsprintfA(buf, "[HOOK] CreateProcessW: child='%s' app='%s' cmd='%s' flags=0x%X cwd='%s'",
                  childBase, appA, cmdA, dwCreationFlags, cwdA);
    }
    Log(buf);

    // OBSERVER MODE (LAUNCHER veya PAYLOAD): pasif gozlem.
    //   * Flags degisme, APC inject yok, manuel ResumeThread yok.
    //   * Launcher: IFEO wrapper inject'i halleder.
    //   * Payload: phase 1 minimal observer, child'a HIC dokunma.
    if (IS_OBSERVER_MODE()) {
        BOOL ok = g_origCreateProcessW(
            lpApplicationName, lpCommandLine,
            lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
        const char* tag = g_launcherMode ? "launcher" : "payload";
        if (ok && lpProcessInformation) {
            wsprintfA(buf, "  -> [%s observe-only] PID=%lu child='%s'",
                      tag, lpProcessInformation->dwProcessId, childBase);
            Log(buf);
        } else if (!ok) {
            wsprintfA(buf, "  -> [%s] CreateProcessW FAILED err=%lu", tag, GetLastError());
            Log(buf);
        }
        return ok;
    }

    BOOL addedSuspend = !(dwCreationFlags & CREATE_SUSPENDED);
    DWORD effectiveFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL ok = g_origCreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, effectiveFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (!ok) {
        wsprintfA(buf, "  -> CreateProcessW FAILED err=%lu", GetLastError());
        Log(buf);
        return ok;
    }

    HANDLE hProcess = lpProcessInformation->hProcess;
    HANDLE hThread  = lpProcessInformation->hThread;
    DWORD  childPid = lpProcessInformation->dwProcessId;
    wsprintfA(buf, "  -> CHILD-W spawned PID=%lu hProc=0x%p hThread=0x%p addedSuspend=%d",
              childPid, hProcess, hThread, addedSuspend);
    Log(buf);

    if (lstrcmpiA(childBase, "GameGuard.des") == 0) {
        g_hGameMonProcess = hProcess;
    }

    ApcInjectChild(hProcess, hThread, childPid);

    if (addedSuspend) {
        DWORD prev = ResumeThread(hThread);
        wsprintfA(buf, "  -> manual ResumeThread (prev suspend count=%lu)", prev);
        Log(buf);
    }
    return ok;
}


BOOL InitCreateProcessHooks() {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        char buf[128];
        wsprintfA(buf, "MH_Initialize FAILED status=%d", s);
        Log(buf);
        return FALSE;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) {
        Log("InitCreateProcessHooks: kernel32 not loaded");
        return FALSE;
    }
    PVOID pCPA = GetProcAddress(hKernel, "CreateProcessA");
    PVOID pCPW = GetProcAddress(hKernel, "CreateProcessW");

    char buf[256];
    wsprintfA(buf, "Hook targets: CreateProcessA=0x%p CreateProcessW=0x%p", pCPA, pCPW);
    Log(buf);

    BOOL allOk = TRUE;
    if (pCPA) {
        s = MH_CreateHook(pCPA, (LPVOID)&HookedCreateProcessA,
                          (LPVOID*)&g_origCreateProcessA);
        if (s != MH_OK) {
            wsprintfA(buf, "MH_CreateHook(CreateProcessA) status=%d", s); Log(buf);
            allOk = FALSE;
        }
    } else { allOk = FALSE; }

    if (pCPW) {
        s = MH_CreateHook(pCPW, (LPVOID)&HookedCreateProcessW,
                          (LPVOID*)&g_origCreateProcessW);
        if (s != MH_OK) {
            wsprintfA(buf, "MH_CreateHook(CreateProcessW) status=%d", s); Log(buf);
            allOk = FALSE;
        }
    } else { allOk = FALSE; }

    s = MH_EnableHook(MH_ALL_HOOKS);
    if (s != MH_OK) {
        wsprintfA(buf, "MH_EnableHook(ALL) status=%d", s); Log(buf);
        return FALSE;
    }
    
    // GetExitCodeProcess in kernelbase.dll
    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
    if (hKernelBase) {
        PVOID pGECP = GetProcAddress(hKernelBase, "GetExitCodeProcess");
        if (pGECP) {
            s = MH_CreateHook(pGECP, (LPVOID)&HookedGetExitCodeProcess, (LPVOID*)&g_origGetExitCodeProcess);
            if (s == MH_OK) MH_EnableHook(pGECP);
        }
    }
    
    // NtQueryInformationProcess in ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        PVOID pNtQIP = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pNtQIP) {
            s = MH_CreateHook(pNtQIP, (LPVOID)&HookedNtQueryInformationProcess, (LPVOID*)&g_origNtQIP);
            if (s == MH_OK) MH_EnableHook(pNtQIP);
        }
    }
    
    Log(allOk ? "MinHook: CreateProcessA/W and NtQueryInformationProcess hooks ACTIVE"
              : "MinHook: hooks partially installed (see warnings above)");
    return allOk;
}


