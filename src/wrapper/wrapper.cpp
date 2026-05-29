// revival_wrapper.exe
//
// Goley_.exe icin IFEO (Image File Execution Options) debugger wrapper.
// Su registry kaydina yerlestiriliyor:
//
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
//     Image File Execution Options\Goley_.exe :: Debugger = <bu .exe>
//
// Kayit yapildiktan sonra her CreateProcess(Goley_.exe) cagrisini Windows
// soyle ceviriyor:
//
//     wrapper.exe <Goley_.exe yolu> <orijinal arg'lar>
//
// Wrapper sirayla: Goley_'i CREATE_SUSPENDED ile spawn et, patcher DLL'i
// inject et, ResumeThread cagir. Goley_ ilk instruction'ini calistirmadan
// once DLL yuklenmis olur, nProtect'in child-side anti-debug'i daha
// silahlanmamis olur, bu yuzden CreateRemoteThread(LoadLibraryA) basarili
// olur. Asil oyun runtime DllMain icinde basliyor.

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

// DLL ve log dosyasinin yollari wmain'de exe'nin kendi konumundan
// hesaplaniyor. Hardcoded path kullanmiyoruz; repo nereye tasinirsa
// dogru yollar otomatik buluyor.
static wchar_t DLL_PATH[MAX_PATH] = {0};
static wchar_t LOG_PATH[MAX_PATH] = {0};

static void Log(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    HANDLE h = CreateFileW(LOG_PATH, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t timed[2200];
        int n = swprintf_s(timed, _countof(timed),
            L"[%02d:%02d:%02d.%03d] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
        DWORD written;
        // Convert to UTF-8 for log file
        char utf8[4400];
        int sz = WideCharToMultiByte(CP_UTF8, 0, timed, n, utf8, _countof(utf8), NULL, NULL);
        if (sz > 0) WriteFile(h, utf8, sz, &written, NULL);
        CloseHandle(h);
    }
}

// Inject DLL into the given (suspended) child process.
// Target process module listesinde verilen basename'i ara.
// Toolhelp32 SNAPMODULE | SNAPMODULE32 -- 32-bit hedef icin de calisir.
static bool VerifyModuleLoaded(DWORD pid, const wchar_t* basename) {
    DWORD flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    for (int retry = 0; retry < 10; ++retry) {
        HANDLE snap = CreateToolhelp32Snapshot(flags, pid);
        if (snap == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_BAD_LENGTH) { Sleep(50); continue; }
            return false;
        }
        MODULEENTRY32W me = { sizeof(me) };
        bool found = false;
        if (Module32FirstW(snap, &me)) {
            do {
                if (lstrcmpiW(me.szModule, basename) == 0) { found = true; break; }
                me.dwSize = sizeof(me);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return found;
    }
    return false;
}

// Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW).
// Child is CREATE_SUSPENDED so its address space is fully initialized AND
// its main thread is paused -- CreateRemoteThread succeeds reliably here.
static bool InjectDll(HANDLE hProcess, DWORD pid, const wchar_t* dllPath) {
    SIZE_T pathBytes = (lstrlenW(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathBytes,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!pRemote) {
        Log(L"InjectDll: VirtualAllocEx FAILED err=%lu", GetLastError());
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemote, dllPath, pathBytes, &written)) {
        Log(L"InjectDll: WriteProcessMemory FAILED err=%lu", GetLastError());
        return false;
    }
    HMODULE hKern = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibW =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKern, "LoadLibraryW");
    if (!pLoadLibW) {
        Log(L"InjectDll: GetProcAddress(LoadLibraryW) FAILED");
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        pLoadLibW, pRemote, 0, NULL);
    if (!hThread) {
        Log(L"InjectDll: CreateRemoteThread FAILED err=%lu", GetLastError());
        return false;
    }
    Log(L"InjectDll: remote LoadLibraryW thread launched, waiting...");
    WaitForSingleObject(hThread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    // exitCode yorumu:
    //   * NTSTATUS exception (0xC0000XXX, 0x80000XXX) -> thread CRASHED
    //   * 0                                            -> LoadLibrary fail
    //   * (HMODULE 32-bit)                             -> success
    bool isException = ((exitCode & 0xF0000000) == 0xC0000000) ||
                       ((exitCode & 0xF0000000) == 0x80000000);
    if (isException) {
        Log(L"InjectDll: remote thread CRASHED NTSTATUS=0x%08lX", exitCode);
    } else if (exitCode == 0) {
        Log(L"InjectDll: LoadLibraryW returned NULL -- load FAILED");
    } else {
        Log(L"InjectDll: LoadLibraryW returned 0x%08lX (HMODULE)", exitCode);
    }

    // Asil success kriteri: target module listesinde gercekten yuklu mu?
    Sleep(200);
    const wchar_t* base = wcsrchr(dllPath, L'\\');
    base = base ? base + 1 : dllPath;
    bool loaded = VerifyModuleLoaded(pid, base);
    Log(L"InjectDll: VerifyModuleLoaded(%s) = %s",
        base, loaded ? L"LOADED OK" : L"NOT FOUND");
    return loaded;
}

// DLL ve log dosyasi yollarini exe'nin kendi konumuna gore hesaplar.
// wrapper.exe su yapida bulunuyor: <repo>/src/wrapper/revival_wrapper.exe
//   DLL_PATH = <repo>/src/patcher/revival_patcher.dll
//   LOG_PATH = <repo>/wrapper.log
static void ResolvePaths(void) {
    wchar_t exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;
    // exePath'i parcala: <repo>\src\wrapper\revival_wrapper.exe
    // Bir seviye yukari -> <repo>\src\wrapper
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (!slash) return;
    *slash = 0;
    // Wrapper'in bulundugu klasor: <repo>\src\wrapper
    wsprintfW(DLL_PATH, L"%s\\..\\patcher\\revival_patcher.dll", exePath);
    // Log: <repo>\wrapper.log (iki seviye yukari)
    wchar_t* up1 = wcsrchr(exePath, L'\\');     // <repo>\src
    if (up1) {
        *up1 = 0;
        wchar_t* up2 = wcsrchr(exePath, L'\\'); // <repo>
        if (up2) { *up2 = 0; }
    }
    wsprintfW(LOG_PATH, L"%s\\wrapper.log", exePath);
}

int wmain(int argc, wchar_t* argv[]) {
    ResolvePaths();
    Log(L"===== wrapper.exe started, argc=%d =====", argc);
    // Raw command-line: Windows'un GetCommandLineW'tan dondurdugu ham string.
    // IFEO redirect sirasinda neyin geldigini netlestirmek icin gerekli.
    LPCWSTR rawCmd = GetCommandLineW();
    Log(L"  raw GetCommandLineW() = %s", rawCmd ? rawCmd : L"<null>");
    for (int i = 0; i < argc; i++) {
        Log(L"  argv[%d] = %s", i, argv[i]);
    }
    // CWD ve env GLY_NO_WRAPPER de raporla
    wchar_t cwd[MAX_PATH] = {0};
    GetCurrentDirectoryW(MAX_PATH, cwd);
    Log(L"  cwd = %s", cwd);

    // argc == 1 -> sadece argv[0] (orig exe path), no args. Geçerli durum,
    // wrapper bunu argumansiz spawn eder. Eskiden "Usage" deyip exit ediyordu;
    // bu revival_tool launch komutunda (argumansiz Goley_.exe) wrapper'i
    // hic is yapmamasina sebep oluyordu.
    if (argc < 1) {
        Log(L"FATAL: argc=0, no orig exe path");
        return 1;
    }

    // ===== Anti-recursion guard =====
    // IFEO Debugger redirection applies to EVERY CreateProcess(Goley_.exe),
    // including the one we make below. Without a guard, our spawn of
    // Goley_.exe gets re-redirected to wrapper.exe (us again) -> fork bomb.
    //
    // We set GLY_NO_WRAPPER=1 in our environment before calling
    // CreateProcessW. The new wrapper instance (which IFEO will spawn)
    // inherits the env, sees the flag, and uses DEBUG_PROCESS to bypass
    // IFEO for its own spawn -- Windows skips IFEO when the parent is
    // already attached as a debugger.
    // IFEO redirects EVERY CreateProcess(Goley_.exe) to wrapper.exe again.
    // DEBUG_PROCESS must be used on the FIRST spawn too, not only when
    // GLY_NO_WRAPPER is inherited -- otherwise wrapper #1 spawns Goley_
    // without DEBUG_PROCESS -> Windows starts wrapper #2 -> inject race /
    // exit 0xC0000005 (see wrapper.log fork-bomb pattern).
    SetEnvironmentVariableW(L"GLY_NO_WRAPPER", L"1");
    DWORD creationFlags = CREATE_SUSPENDED | DEBUG_PROCESS;
    DWORD chainLen = GetEnvironmentVariableW(L"GLY_NO_WRAPPER", NULL, 0);
    if (chainLen > 0)
        Log(L"GLY_NO_WRAPPER inherited -- spawn with DEBUG_PROCESS (IFEO bypass)");
    else
        Log(L"First wrapper instance -- GLY_NO_WRAPPER=1, DEBUG_PROCESS spawn");

    // IFEO konvention'i caller'a gore DEGISIR (kanitlandi):
    //   Durum A (revival_tool launch): argv[0]=Goley_.exe basename, argv[1+]=args
    //   Durum B (wrapper self-spawn): argv[0]=wrapper.exe full path, argv[1]=Goley_.exe, argv[2+]=args
    // Yani argv[0]'i kosulsuz exePath kabul etmek FORK BOMB'a yol acar:
    //   wrapper self-spawn DEBUG_PROCESS'te argv[0]=wrapper.exe -> exePath=wrapper.exe
    //   -> wrapper sonsuz kendisi spawn -> 1163 instance.
    //
    // Cozum: argv[0] basename'ini kontrol et.
    //   wrapper.exe ise -> argv[1] orig exe, argv[2+] args
    //   degilse        -> argv[0] orig exe, argv[1+] args
    int argStart;
    std::wstring exePath;
    {
        const wchar_t* a0base = wcsrchr(argv[0], L'\\');
        a0base = a0base ? a0base + 1 : argv[0];
        if (_wcsicmp(a0base, L"revival_wrapper.exe") == 0) {
            if (argc < 2) {
                Log(L"FATAL: argv[0]=wrapper.exe ama argv[1] yok -- recursion limiti");
                return 1;
            }
            exePath  = argv[1];
            argStart = 2;
            Log(L"  detected: argv[0]=wrapper.exe (self-spawn shape), exePath=argv[1]=%s",
                argv[1]);
        } else {
            exePath  = argv[0];
            argStart = 1;
            Log(L"  detected: argv[0]=orig exe (IFEO redirect shape), exePath=argv[0]=%s",
                argv[0]);
        }
    }

    std::wstring cmdLine;
    cmdLine += L"\"";
    cmdLine += exePath;
    cmdLine += L"\"";
    for (int i = argStart; i < argc; i++) {
        cmdLine += L" ";
        cmdLine += argv[i];
    }

    Log(L"Spawning: exe='%s' creationFlags=0x%X", exePath.c_str(), creationFlags);
    Log(L"Cmdline:  %s", cmdLine.c_str());

    std::wstring cmdBuf = cmdLine;

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(
        exePath.c_str(),
        &cmdBuf[0],
        NULL, NULL, FALSE,
        creationFlags,
        NULL, NULL,
        &si, &pi);

    // If DEBUG_PROCESS was used, detach RIGHT NOW (before InjectDll).
    // Without detach, the child's threads are throttled waiting for our
    // (nonexistent) debugger event loop, so CreateRemoteThread(LoadLibraryW)
    // never executes. After DebugActiveProcessStop the child is a normal
    // CREATE_SUSPENDED process and our injection succeeds.
    if (ok && (creationFlags & DEBUG_PROCESS)) {
        DebugSetProcessKillOnExit(FALSE);
        BOOL detached = DebugActiveProcessStop(pi.dwProcessId);
        Log(L"DebugActiveProcessStop (early detach) returned %d", detached);
    }
    if (!ok) {
        Log(L"CreateProcessW FAILED err=%lu", GetLastError());
        return 1;
    }
    Log(L"CreateProcess OK PID=%lu (suspended)", pi.dwProcessId);

    // Inject our patcher DLL while the child is suspended. At this point
    // the child's main thread is created but paused -- nProtect's child-
    // side self-protect code hasn't run yet, so CreateRemoteThread works.
    bool injected = InjectDll(pi.hProcess, pi.dwProcessId, DLL_PATH);
    Log(L"InjectDll returned %s", injected ? L"OK" : L"FAIL");

    // If we attached as debugger (recursive call), detach now so child
    // runs free. Without detach, the OS expects us to pump debug events,
    // which we don't.
    if (creationFlags & DEBUG_PROCESS) {
        BOOL detached = DebugActiveProcessStop(pi.dwProcessId);
        Log(L"DebugActiveProcessStop returned %d (detached debugger)", detached);
    }

    // No Sleep between inject and Resume -- the dnight 22:46 baseline
    // (which actually produced a visible splash and a stable PID for 80+s)
    // had no sleep here. Both Sleep(300) and Sleep(80) broke Themida's
    // internal unpack timer; the unpacker hung at val=0 forever.
    DWORD resumed = ResumeThread(pi.hThread);
    Log(L"ResumeThread returned %lu (prev suspend count)", resumed);

    // Wait for child to exit, then return its exit code (Windows debugger
    // protocol: the debugger should wait on the debuggee).
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    Log(L"Child exited with code %lu", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)exitCode;
}
