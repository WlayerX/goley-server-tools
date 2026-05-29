#include "patcher_main.h"
#include "../core/logger.h"
#include "../core/helpers.h"
#include "../core/memory.h"
#include "../hooks/hook_process.h"
#include "../hooks/hook_wait.h"
#include "../hooks/hook_network.h"
#include "../hooks/hook_cmdline.h"
#include "../hooks/hook_window.h"
#include "../hooks/hook_bugtrap.h"
#include "../hooks/hook_netmarble.h"
#include "../hooks/hook_exit.h"
#include "../hooks/hook_ipc.h"
#include "../bypass/hwbp.h"
#include "../bypass/veh_handler.h"
#include "../bypass/anticheat.h"

DWORD WINAPI PatchThread(LPVOID lpParam) {
    // =========================================================
    // OBSERVER MODE PATH (LAUNCHER veya PAYLOAD)
    // =========================================================
    // LAUNCHER MODE (Goley.exe) -- Themida'siz, kisa-omurlu:
    //   1. CreateProcessA/W hook -> CHILD AUDIT-ONLY (inject yok, IFEO wrapper halleder)
    //   2. NMRunParamLauncherHooks -> SetParam/SetParam2/RunProgram observer
    //   3. Network hooks -> DNS/HTTP audit
    //   4. Periyodik modul snapshot
    //
    // PAYLOAD MODE (BinaryTr.bin) phase 1 -- minimal observer:
    //   1. CreateProcessA/W hook -> CHILD AUDIT-ONLY (inject yok)
    //   2. Raw GetCommandLine() log
    //   3. Network hooks -> DNS/HTTP audit
    //   4. Window audit hooks -> RegisterClassEx/CreateWindowEx audit
    //   5. Periyodik modul snapshot
    //   NMRun fake YOK, fake cmdline YOK, BugTrap hook YOK, inline patch YOK,
    //   VEH YOK, ScyllaHide YOK. Phase 2'de kademeli eklenir.
    //
    // STUB MODE (Goley_.exe) -- bu observer branch'e GIRMEZ, asagidaki game body.
    // Observer mode = launcher VEYA payload. Ikisi de minimal hook seti alir:
    // CreateProcess + (launcher) NMRun launcher hooks + Network. Inline patches,
    // VEH, BugTrap, fake cmdline, window audit -- skip.
    if (IS_OBSERVER_MODE()) {
        if (g_launcherMode)
            Log("PatchThread starting (LAUNCHER MODE -- cerrahi gozlemci)");
        else
            Log("PatchThread starting (PAYLOAD MODE phase 1 -- minimal observer)");
        // MH_Initialize InitCreateProcessHooks icinde cagriliyor.
        InitCreateProcessHooks();
        // Raw command-line log (payload icin kritik -- gercek argv ne?)
        {
            LPCSTR rawA = GetCommandLineA();
            char rbuf[1024];
            wsprintfA(rbuf, "RAW GetCommandLineA() = %.900s", rawA ? rawA : "<null>");
            Log(rbuf);
        }
        BOOL nmInstalled   = FALSE;
        BOOL netInstalled  = FALSE;
        BOOL audInstalled  = FALSE;
        DWORD startTick = GetTickCount();
        DWORD lastSnap  = 0;
        const char* tag = g_launcherMode ? "launcher" : "payload";
        while (TRUE) {
            // NMRun launcher hooks SADECE launcher icin (Goley.exe param push'u
            // yakalamak). Payload tarafinda NMRun OKUYAN cagrilarini fake mode'a
            // sokmak isteriz ama phase 1'de fake yok -- skip.
            if (g_launcherMode && !nmInstalled && InitNMRunParamLauncherHooks()) {
                nmInstalled = TRUE;
                Log("NMRun launcher hooks installed (observer-only)");
            }
            if (!netInstalled && InitNetworkHooks()) {
                netInstalled = TRUE;
                char b[200];
                wsprintfA(b, "Network hooks installed (%s mode -- DNS/HTTP audit)", tag);
                Log(b);
            }
            // Window audit -- payload icin kritik (gercek pencereyi yakalamak).
            // Launcher zaten pencere ac yok, harmless.
            if (!audInstalled && InitWindowAuditHooks()) {
                audInstalled = TRUE;
                Log("Window audit hooks installed (observer-only)");
            }
            DWORD now = GetTickCount();
            char snapTag[40];
            if (lastSnap == 0 && (now - startTick) > 1000) {
                lastSnap = now;
                wsprintfA(snapTag, "%s-initial", tag);
                LogLoadedModulesSnapshot(snapTag);
            } else if (lastSnap != 0 && (now - lastSnap) > 30000) {
                lastSnap = now;
                wsprintfA(snapTag, "%s-periodic-30s", tag);
                LogLoadedModulesSnapshot(snapTag);
            }
            Sleep(500);
        }
        return 0;  // unreachable
    }
    // =========================================================
    // GAME MODE PATH -- Goley_.exe icin full armor (asagisi mevcut kod)
    // =========================================================
    Log("PatchThread starting (VEH+HWBP+MinHook refresh-loop mode)");

    // ScyllaHide DllMain'de yuklendi.

    // Install kernel32!CreateProcessA/W hooks FIRST so the very first
    // child spawn (typically nProtect's GameMon.des) gets our DLL APC-injected.
    InitCreateProcessHooks();

    // ntdll-level exit interception via MinHook (NtTerminateProcess /
    // RtlExitUserProcess). Installed EARLY and BEFORE we PatchHangStub these
    // stubs anywhere -- MinHook must see clean prologues to trampoline. These
    // log the full caller stack to patcher_crash.log so we can finally see the
    // call site of the silent termination. Falls back to PatchHangStub per-stub
    // if trampolining the short syscall stub fails.
    {
        int ne = InitExitHooks();
        char eb[96];
        wsprintfA(eb, "Exit-API interception installed: %d ntdll stub(s) via MinHook", ne);
        Log(eb);
    }

    // Wait hooks ENABLED IMMEDIATELY so we catch the early nProtect wait.
    // GameGuard might detect this and try to kill the process, but our inline
    // PatchHangStub (DllMain) will just freeze that anti-debug thread.
    Log("Wait hooks ENABLED immediately");
    InitWaitHooks();

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) { Log("GetModuleHandle NULL"); return 1; }
    g_imageBase = (BYTE*)hMod;

    char buf[256];
    wsprintfA(buf, "Image base: 0x%p", g_imageBase);
    Log(buf);

    // VEH already installed inline from DllMain ATTACH (race fix).
    if (g_vehHandle) {
        Log("VEH already installed (inline from DllMain)");
    } else {
        g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
        if (!g_vehHandle) {
            Log("AddVectoredExceptionHandler FAILED");
            return 1;
        }
        Log("VEH installed by PatchThread (fallback)");
    }

    // Hook ExitProcess + TerminateProcess so we can capture the call site
    // that's killing us ~8 seconds after VEH-bypass.
    int killHooks = HookKillApis();
    char hbuf[64];
    wsprintfA(hbuf, "Kill API hooks installed: %d slot(s)", killHooks);
    Log(hbuf);

    DWORD valVA = (DWORD)(g_imageBase + VALIDATION_RVA);

    // PLAN: IAT slot hijack for Goley_'s MessageBoxW call site.
    // Disasm of the unpacked binary at 0xD35585 showed:
    //   call [0x019984D4]   ; user32!MessageBoxW via IAT
    // We rewrite the slot to point at our FakeMessageBoxW which returns IDOK
    // without showing any dialog. This is the cleanest bypass:
    //   - No write on user32 (anti-tamper friendly)
    //   - No HW BP (anti-debug friendly)
    //   - No DR registers (Themida-friendly)
    //
    // Note: at DLL_PROCESS_ATTACH time, Goley_'s IAT may not yet contain the
    // real MessageBoxW pointer (Themida fills it after unpack). So we retry
    // every refresh iteration below until the slot value looks "real".

    wsprintfA(buf, "Targets: validation=0x%X  MessageBoxW-IAT=0x%X (will hijack after unpack)",
              valVA, GOLEY_MBW_IAT_VA);
    Log(buf);

    // Inline-stub kernel32!ExitProcess + TerminateProcess so any "init
    // failed -> suicide" cleanup can't actually kill the process. nProtect
    // doesn't hash-check kernel32 (only user32 in the tests above).
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        DWORD termVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "TerminateProcess");
        DWORD exitVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "ExitProcess");
        PatchHangStub(termVA, "kernel32!TerminateProcess");
        PatchHangStub(exitVA, "kernel32!ExitProcess");
    }

    // ALSO patch the ntdll-level process kill APIs. Themida-packed code
    // often bypasses kernel32 wrappers and calls these syscall stubs
    // directly. Without patching them too, Goley_ can exit despite our
    // kernel32 patches.
    //
    //   NtTerminateProcess(HANDLE, NTSTATUS) -- 2 args -> ret 8
    //   RtlExitUserProcess(UINT)             -- 1 arg  -> ret 4
    //   NtTerminateThread (HANDLE, NTSTATUS) -- 2 args -> ret 8  (defensive)
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (hNt) {
        // NOTE: NtTerminateProcess / RtlExitUserProcess are intercepted by
        // InitExitHooks() above (MinHook logging hooks, with PatchHangStub
        // fallback). Do NOT PatchHangStub them here -- that would corrupt the
        // prologue MinHook needs and silence the call-site capture.
        // ntdll!NtCreateUserProcess is the REAL syscall that creates a process
        // on modern Windows. kernel32!CreateProcessA/W and internal variants
        // all funnel through it. Goley_'s Themida bypass goes straight here.
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            g_createProcessWVA = (DWORD)(ULONG_PTR)GetProcAddress(hNtdll, "NtCreateUserProcess");
            wsprintfA(buf, "ntdll!NtCreateUserProcess resolved at 0x%X", g_createProcessWVA);
            Log(buf);
        }
        // BLOCK CreateProcess: any call returns FALSE without spawning a child.
        // This prevents Goley_'s "trusted re-launch" pattern. Parent process
        // already has all our bypasses applied, so it can continue solo.
        // ret 40 = stdcall cleanup for 10 args (HWND, ..., lpProcessInformation)
        // CreateProcess block disabled -- Goley_ bypasses kernel32 entirely
        // via direct NtCreateUserProcess syscall, so blocking these doesn't
        // prevent the child spawn. Child inject is handled by the PowerShell
        // watcher using NtCreateThreadEx (less restrictive than CRT).
    }

    // Refresh loop: ONLY DR0 is used, for the Themida validation branch
    // (one-shot). After val hits, we ALSO try to hijack the MessageBoxW
    // IAT slot at GOLEY_MBW_IAT_VA. The slot may be empty/0xFFFFFFFF at
    // DLL_PROCESS_ATTACH time (Themida hasn't filled imports yet); we
    // retry on every iteration until we see a real pointer there.
    int iterations = 0;
    int totalHWBPSets = 0;
    DWORD startTick = GetTickCount();
    BOOL valSweepDone = FALSE;
    BOOL iatHijacked = FALSE;
    BOOL ggrSweepDone = FALSE;
    BOOL waitHooksInstalled = FALSE;
    BOOL nmrunHooksInstalled = FALSE;
    while (TRUE) {  // sonsuz loop: process oldukce patcher de yasar
        // (0) NMRunParam GAME hooks -- Goley_.exe (game client) icin tum 7
        //     hook + fake mode + preload. Bu game-mode body'si, launcher
        //     buraya hic gelmez (yukarida ayri PatchThread branch'i var).
        if (!nmrunHooksInstalled && InitNMRunParamGameHooks()) {
            nmrunHooksInstalled = TRUE;
            Log("NMRun game hooks installed (full fake param mode)");
        }
        // Network hooks (ws2_32). ws2_32 cogu zaman startup'ta yuklu degil;
        // Goley_ network init'ine geldiginde yuklenir. Her saniye check.
        static BOOL netHooksInstalled = FALSE;
        if (!netHooksInstalled && InitNetworkHooks()) {
            netHooksInstalled = TRUE;
            Log("Network hooks installed (ws2_32 connect/DNS)");
        }
        // GetCommandLine hooks -- "NoPopup" inject ederek WinMain
        // "Please run Goley.exe" dialog'unu by-pass et.
        static BOOL gclHooksInstalled = FALSE;
        if (!gclHooksInstalled && InitCmdLineHooks()) {
            gclHooksInstalled = TRUE;
            Log("GetCommandLine hooks installed (NoPopup injection)");
        }
        // EVIDENCE-ONLY: dialog kaynak tespiti icin pasif audit hook'lar.
        // Davranis degistirmez, sadece her CreateWindowEx/RegisterClassEx
        // cagrisini caller modul + RVA ile logla. 371x143 match'inde
        // ozel "*** SUSPECT DIALOG MATCH ***" satiri bas.
        static BOOL winAuditInstalled = FALSE;
        if (!winAuditInstalled && InitWindowAuditHooks()) {
            winAuditInstalled = TRUE;
            Log("Window audit hooks installed (evidence-only)");
            // Hemen bir snapshot al -- hooks kuruldugu anki modul listesi.
            LogLoadedModulesSnapshot("post-WinAudit-install");
        }
        // BugTrap dialog bypass -- A+B+C katmanli savunma:
        //   A. BT_SaveSnapshot -> return 1 (success, snapshot save bypass)
        //   B. BT_SendSnapshot -> return 1 (success, dialog acilmaz)
        //   C. BT_SetFlags    -> orig(0) silent mode zorla
        // BugTrap.dll Goley_ tarafindan startup'ta yuklenir, ama tam zamani
        // belirsiz -- her iterasyonda GetModuleHandle ile kontrol.
        static BOOL bugTrapHooksInstalled = FALSE;
        if (!bugTrapHooksInstalled && InitBugTrapHooks()) {
            bugTrapHooksInstalled = TRUE;
            Log("BugTrap hooks installed (A+B+C dialog bypass)");
        }
        // IPC/heartbeat observer hooks -- detect GameGuard shared-memory or
        // driver (DeviceIoControl) handshake the sleeping dummy_gg.exe fails.
        // Pure pass-through logging, evidence-only.
        static BOOL ipcHooksInstalled = FALSE;
        if (!ipcHooksInstalled && InitIpcHooks()) {
            ipcHooksInstalled = TRUE;
            Log("IPC observer hooks installed (CreateFileMapping/MapViewOfFile/DeviceIoControl)");
        }

        // (1) Once val hits, sweep-clear DRx (Themida anti-debug friendliness)
        if (g_valHit && !valSweepDone) {
            Log("Validation hit -- one final DRx sweep clear");
            int c = ClearHardwareBreakpointAllThreads();
            wsprintfA(buf, "DRx cleared on %d threads", c);
            Log(buf);
            valSweepDone = TRUE;
        }

        // (1b) Thread-EIP polling -- every 15 sec, enumerate every thread
        //      in this process, suspend, read EIP+ESP, resume. Log lines
        //      whose EIP is inside ntdll!Zw* / kernelbase!Wait* / a few
        //      well-known wait stubs. The return address read from [ESP+0]
        //      tells us which Goley_ code site is parked on a wait.
        DWORD nowTick = GetTickCount();

        // 1 Hz heartbeat -- when the process dies silently, the LAST heartbeat
        // line in patcher.log bounds the death window (and confirms the patch
        // thread itself was still alive right before the exit).
        static DWORD g_lastHeartbeat = 0;
        if ((nowTick - g_lastHeartbeat) > 1000) {
            g_lastHeartbeat = nowTick;
            wsprintfA(buf, "HB iter=%d valHit=%d ggrHit=%d mbwHit=%d cpHit=%d tick=%lu",
                      iterations, g_valHit, g_ggrHit, g_mbwHit, g_cpHit, nowTick);
            Log(buf);
        }

        if ((nowTick - startTick) > 10000 &&
            (nowTick - g_lastThreadDumpTick) > 15000) {
            g_lastThreadDumpTick = nowTick;
            DumpThreadEips();
        }

        // Periyodik modules snapshot -- nProtect/GameGuard sonradan
        // LoadLibrary yapabiliyor. Her ~30 sn'de bir liste guncellensin.
        // (evidence-only)
        static DWORD g_lastModuleSnapTick = 0;
        if (g_lastModuleSnapTick != 0 &&
            (nowTick - g_lastModuleSnapTick) > 30000) {
            g_lastModuleSnapTick = nowTick;
            LogLoadedModulesSnapshot("periodic-30s");
        } else if (g_lastModuleSnapTick == 0 &&
                   (nowTick - startTick) > 5000) {
            // Ilk periyodik snapshot 5 sn sonra (install-anindaki
            // snapshot'i tekrar etmemek icin gecikme).
            g_lastModuleSnapTick = nowTick;
        }

        // (Wait hooks are now initialized immediately at startup)

        // (1b) Once GG result hits, sweep-clear DRx again (critical: Themida
        //      anti-debug probe kills us in ~2 sec if any DR1/DR2 stay set)
        if (g_ggrHit && !ggrSweepDone) {
            Log("GG result hit -- second DRx sweep clear");
            int c = ClearHardwareBreakpointAllThreads();
            wsprintfA(buf, "DRx cleared on %d threads (after GG result)", c);
            Log(buf);
            ggrSweepDone = TRUE;
        }

        // (2) After val hit, Themida has resolved imports. Scan the entire
        //     process memory for the resolved MessageBoxW address and
        //     replace EVERY occurrence with our FakeMessageBoxW. This
        //     handles Themida's obfuscated IAT (the original IAT VA is
        //     MEM_FREE at runtime; the real function pointers live in
        //     Themida-allocated regions).
        //     Done ONCE, ~1 second after val hit (gives nProtect DLL
        //     time to also resolve its imports).
        // (2) GameGuard daemon kill defensive. Apply ONCE, 1.5s after val
        //     hit. We DROPPED the memory-write patches at 0xD39A11/0xD35585
        //     because the runtime bytes at 0xD35585 are NOT the static-
        //     disasm bytes -- Themida replaced the original `call [IAT]`
        //     with a relative `call ThemidaVMStub` at unpack time. Memory
        //     writes there trigger Themida's runtime tamper check and
        //     suicide within seconds.
        //
        //     The MessageBoxW CALL is now intercepted via HW BP DR1 in the
        //     VEH handler (see mbwVA check above), which doesn't write to
        //     code memory and bypasses tamper detection.
        if (g_valHit && !iatHijacked && iterations >= 30) {
            // Multiple patch sites to neutralize GameGuard error dialog and
            // the cmp/jne chain that routes to it. Apply all in one pass.
            // Memory writes intentionally omitted -- MessageBoxW CALL is
            // handled via HW BP DR1 (see VEH handler).

            // Defensive: kill GameMon.des / GameMon64.des daemons even though
            // they don't currently spawn for Goley_ (driver init failed before
            // daemon launch). In case nProtect retries the spawn later.
            const char* daemons[] = { "GameMon.des", "GameMon64.des", NULL };
            for (int i = 0; daemons[i]; i++) {
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == INVALID_HANDLE_VALUE) continue;
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (lstrcmpiA(pe.szExeFile, daemons[i]) == 0) {
                            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hProc) {
                                TerminateProcess(hProc, 9);
                                CloseHandle(hProc);
                                wsprintfA(buf, "Killed daemon %s pid=%lu", daemons[i], pe.th32ProcessID);
                                Log(buf);
                            }
                        }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }

            iatHijacked = TRUE;
        }

        // (3) HW BP layout:
        //   DR0 = val bypass (0xD3DC4D) -- one-shot, disarmed after first hit
        //   DR1 = MessageBoxW CALL (0xD35586) -- catches the dialog if the
        //         primary bypass somehow misses
        //   DR2 = GG CHECK CALL (0xD35374) -- PRIMARY bypass, structural
        //         skip of the entire GG status check
        DWORD t0 = g_valHit ? 0 : valVA;
        // MessageBoxW: keep persistent until GG result hits (after that the
        // dialog path is structurally bypassed, no need to catch MBW).
        DWORD t1 = g_ggrHit ? 0 : (DWORD)(g_imageBase + GG_MBW_CALL_RVA);
        // GG result: one-shot. Once hit, NEVER re-arm (Themida anti-debug
        // probes DRx periodically and persistent set kills us in ~2 sec).
        DWORD t2 = g_ggrHit ? 0 : (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
        // CreateProcessW hook: one-shot. Fires when parent re-execs the
        // child Goley_, adds CREATE_SUSPENDED so we can inject before run.
        // Uses kernel32!CreateProcessW entry point so ANY caller is caught.
        DWORD t3 = g_cpHit ? 0 : g_createProcessWVA;
        int n = SetHardwareBreakpointAllThreads(t0, t1, t2, t3);
        totalHWBPSets += n;
        iterations++;

        if (iterations % 40 == 0) {
            wsprintfA(buf, "iter %d total_set=%d hits[val=%d] iat=%d",
                      iterations, totalHWBPSets, g_valHit, iatHijacked);
            Log(buf);
        }

        // If both done and a few seconds have passed, slow the loop.
        if (g_valHit && iatHijacked && iterations > 200) {
            Sleep(500);
        } else {
            Sleep(50);  // 20Hz refresh
        }
    }

    Log("PatchThread loop exit");
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        ResolveLogPath(hModule);

        // ====================================================================
        // PROCESS MODE DETECTION (4 modes -- her process kendi davranisina sahip)
        // ====================================================================
        //  1. LAUNCHER MODE = Goley.exe          (Joygame TR launcher, gozlemci)
        //  2. WRAPPER MODE  = revival_wrapper.exe (IFEO debugger stub, no-op)
        //  3. STUB MODE     = Goley_.exe         (Themida'li chain loader)
        //  4. PAYLOAD MODE  = BinaryTr.bin        (gercek game payload)
        // STUB ve PAYLOAD ikisi de full armor alir (mevcut "game mode" davranisi),
        // sadece log dosyasi ve etiket ayri.
        //
        // WRAPPER MODE en kritik: HIC PATCH YAPMAYACAK. Patcher.dll inject olsa
        // bile wrapper.cpp kendi mantigini calistirmali. Aksi takdirde armor
        // recursion'a engel olamiyor -> fork bomb (3944 wrapper instance!).
        char selfBasename[64] = {0};
        {
            char selfExe[MAX_PATH] = {0};
            if (GetModuleFileNameA(NULL, selfExe, MAX_PATH) > 0) {
                const char* base = strrchr(selfExe, '\\');
                base = base ? base + 1 : selfExe;
                lstrcpynA(selfBasename, base, sizeof(selfBasename));
            }
        }

        if (lstrcmpiA(selfBasename, "revival_wrapper.exe") == 0 ||
            lstrcmpiA(selfBasename, "GameGuard.des") == 0 ||
            lstrcmpiA(selfBasename, "GameMon.des") == 0) {
            // === WRAPPER/GAMEGUARD MODE -- EARLY RETURN, hicbir patch/hook/armor ===
            // Wrapper veya hile korumasi kendi mantigini calistirmali. patcher.dll burada
            // is yapmamali. Log dosyasi = patcher_ignored.log.
            char* slash = (char*)strrchr(g_logPath, '\\');
            if (slash) lstrcpyA(slash + 1, "patcher_ignored.log");
            Log("DLL_PROCESS_ATTACH [IGNORED MODE] -- EARLY RETURN, no patches");
            return TRUE;  // hicbir armor, hook, VEH, ScyllaHide yok
        }

        bool isLauncher = (lstrcmpiA(selfBasename, "Goley.exe") == 0);
        bool isPayload  = (lstrcmpiA(selfBasename, "BinaryTr.bin") == 0);
        // STUB MODE   = Goley_.exe    (full armor -- Themida bypass + dialog kill)
        // PAYLOAD MODE= BinaryTr.bin  (phase 1 MINIMAL observer -- no armor,
        //                              crash 0xC0000005'i observe et, sonra
        //                              kademeli hook ekle)

        if (isLauncher) {
            InterlockedExchange(&g_launcherMode, 1);
            // log: patcher_launcher.log
            char* slash = (char*)strrchr(g_logPath, '\\');
            if (slash) lstrcpyA(slash + 1, "patcher_launcher.log");
        } else if (isPayload) {
            // log: patcher_payload.log -- gercek game runtime'i ayri izle
            InterlockedExchange(&g_payloadMode, 1);
            char* slash = (char*)strrchr(g_logPath, '\\');
            if (slash) lstrcpyA(slash + 1, "patcher_payload.log");
        }
        // else: STUB MODE (Goley_.exe), default patcher.log

        // Konsol sadece uzun-omurlu process'lerde ac (launcher kisa-omurlu).
        if (!g_launcherMode) {
            InitDebugConsole();
        }

        if (g_launcherMode) {
            Log("DLL_PROCESS_ATTACH [LAUNCHER MODE]  (Goley.exe)");
            Log("launcher passive observer: no ScyllaHide, no VEH, no inline patches, no child inject");
            Log("=== patcher_launcher.log dosyasini izle ===");
        } else if (isPayload) {
            Log("DLL_PROCESS_ATTACH [PAYLOAD MODE]  (BinaryTr.bin)");
            Log("payload phase 1 minimal observer: no ScyllaHide, no VEH, no inline patches, no fake cmdline, no child inject");
            Log("active: CreateProcess audit + raw cmdline log + network + window audit + module snapshot");
            Log("=== patcher_payload.log dosyasini izle ===");
        } else {
            Log("DLL_PROCESS_ATTACH [STUB MODE]  (Goley_.exe Themida chain loader)");
            Log("full armor (VEH+HWBP+DialogKiller+BugTrap+ScyllaHide+inline patches+fake cmdline)");
            Log("self-exec detection log-only -- expect to spawn BinaryTr.bin PAYLOAD");
        }

        // ====================================================================
        // ARMOR SETUP -- launcher mode'da TAMAMEN SKIP. Launcher Themida'siz
        // bir EXE; bu agresif patch'ler onun normal akisini zehirleyebilir.
        //   * ScyllaHide        -> skip
        //   * MessageBox/Dialog -> skip
        //   * GetCommandLine    -> skip
        //   * TerminateProcess  -> skip
        //   * ExitProcess       -> skip
        //   * NtTerminate*      -> skip
        //   * VEH               -> skip
        //   * DialogKiller      -> skip
        // Launcher SADECE PatchThread'i alir; orada da CreateProcess +
        // NMRunParam + Network hook'lari yuklenir (cerrahi gozlemci).
        // PAYLOAD MODE (BinaryTr.bin) phase 1 = launcher gibi minimal,
        // crash 0xC0000005 observe etmek icin armor skip.
        // STUB MODE (Goley_.exe) icin asagidaki blok TAM AKTIF.
        // ====================================================================
        if (!IS_OBSERVER_MODE()) {
            // ScyllaHide HookLibrary'i HEMEN yukle. Onceki seans dataya gore
            // DllMain'de yuklendiginde Themida tamper detection tetiklenmiyor
            // (90+ sn 0 exception). PatchThread'den gec yukleninde flood var.
            {
                char selfPath[MAX_PATH] = {0};
                if (GetModuleFileNameA(hModule, selfPath, MAX_PATH) > 0) {
                    char* slash = strrchr(selfPath, '\\');
                    if (slash) {
                        *slash = 0;
                        char scyllaPath[MAX_PATH];
                        wsprintfA(scyllaPath, "%s\\..\\scyllahide\\HookLibraryx86.dll", selfPath);
                        HMODULE hSH = LoadLibraryA(scyllaPath);
                        char buf[400];
                        if (hSH) wsprintfA(buf, "ScyllaHide loaded at 0x%p (DllMain)", hSH);
                        else     wsprintfA(buf, "ScyllaHide load FAILED: %lu", GetLastError());
                        Log(buf);
                    }
                }
            }

            // INLINE user32 dialog/messagebox API'leri: dialog HIC cikmasin
            // diye hepsini "mov eax,1; ret N" stub'larina overrider yap.
            // Dialog yeni Themida tampering check trigger ediyor ve WinMain
            // return 0'a goturuyor.
            {
                HMODULE hUser = LoadLibraryA("user32.dll");
                if (hUser) {
                    struct DlgStub { const char* name; int argBytes; };
                    DlgStub stubs[] = {
                        { "MessageBoxA",                  16 },  // 4 args
                        { "MessageBoxW",                  16 },
                        { "MessageBoxExA",                20 },  // 5 args
                        { "MessageBoxExW",                20 },
                        { "MessageBoxIndirectA",           4 },  // 1 arg (LPMSGBOXPARAMS*)
                        { "MessageBoxIndirectW",           4 },
                        { "DialogBoxParamA",              20 },  // 5 args
                        { "DialogBoxParamW",              20 },
                        { "DialogBoxIndirectParamA",      20 },
                        { "DialogBoxIndirectParamW",      20 },
                    };
                    for (int i = 0; i < (int)(sizeof(stubs)/sizeof(stubs[0])); i++) {
                        BYTE* fn = (BYTE*)GetProcAddress(hUser, stubs[i].name);
                        if (!fn) continue;
                        // mov eax, 1; ret <argBytes>  = B8 01 00 00 00  C2 XX 00
                        BYTE stub[8] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2,
                                         (BYTE)stubs[i].argBytes, 0x00 };
                        DWORD oldProt;
                        if (VirtualProtect(fn, 8, PAGE_EXECUTE_READWRITE, &oldProt)) {
                            memcpy(fn, stub, 8);
                            VirtualProtect(fn, 8, oldProt, &oldProt);
                            char b[200];
                            wsprintfA(b, "Patched [inline] user32!%s -> mov eax,1; ret %d",
                                      stubs[i].name, stubs[i].argBytes);
                            Log(b);
                        }
                    }
                }
            }

            // INLINE GetCommandLineA/W patch -- WinMain'in dialog'unu
            // (Please run Goley.exe) onlemek icin lpCmdLine'da "NoPopup"
            // gorunmesini sagla. PatchThread'in async hook'u cok gec; biz
            // DllMain'de fonksiyonun ilk 6 byte'ini "mov eax, imm32; ret"
            // ile inline overrider yapiyoruz.
            {
                HMODULE hKernel = GetModuleHandleA("kernel32.dll");
                if (hKernel) {
                    BYTE* pA = (BYTE*)GetProcAddress(hKernel, "GetCommandLineA");
                    BYTE* pW = (BYTE*)GetProcAddress(hKernel, "GetCommandLineW");
                    BYTE stubA[6] = { 0xB8, 0,0,0,0, 0xC3 };
                    BYTE stubW[6] = { 0xB8, 0,0,0,0, 0xC3 };
                    DWORD addrA = (DWORD)(ULONG_PTR)g_fakeCmdLineA;
                    DWORD addrW = (DWORD)(ULONG_PTR)g_fakeCmdLineW;
                    memcpy(&stubA[1], &addrA, 4);
                    memcpy(&stubW[1], &addrW, 4);
                    DWORD oldProt;
                    if (pA && VirtualProtect(pA, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                        memcpy(pA, stubA, 6);
                        VirtualProtect(pA, 6, oldProt, &oldProt);
                        Log("Patched [inline] kernel32!GetCommandLineA -> mov eax,fake; ret");
                    }
                    if (pW && VirtualProtect(pW, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                        memcpy(pW, stubW, 6);
                        VirtualProtect(pW, 6, oldProt, &oldProt);
                        Log("Patched [inline] kernel32!GetCommandLineW -> mov eax,fake; ret");
                    }
                }
            }

            // ============================================================
            // INLINE early armor -- runs in DllMain BEFORE any async thread.
            // ============================================================
            // Race issue: wrapper.exe calls LoadLibraryW(us) and ResumeThread()
            // back-to-back. As soon as ResumeThread fires, Themida starts
            // unpacking. On a warm system that takes ~7 ms to reach
            // ExitProcess/TerminateProcess for any of its anti-debug paths.
            // Our async PatchThread doesn't finish MinHook + kill-API
            // patching for ~40 ms, so the race is lost and the child exits
            // before we install anything.
            //
            // Solution: install kill-API stubs INLINE here, in the loader
            // lock context. VirtualProtect + memcpy are kernel32 ops, very
            // fast (sub-millisecond) and safe under loader lock. After
            // DllMain returns, the wrapper's ResumeThread proceeds and
            // Themida unpack starts -- by then TerminateProcess/ExitProcess
            // /Nt{Terminate,Exit}* all return success without doing anything.
            {
                HMODULE hKernel = GetModuleHandleA("kernel32.dll");
                HMODULE hNt     = GetModuleHandleA("ntdll.dll");
                if (hKernel) {
                    DWORD termVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "TerminateProcess");
                    DWORD exitVA = (DWORD)(ULONG_PTR)GetProcAddress(hKernel, "ExitProcess");
                    PatchHangStub(termVA, "[inline] kernel32!TerminateProcess");
                    PatchHangStub(exitVA, "[inline] kernel32!ExitProcess");
                }
                // ntdll!NtTerminateProcess / RtlExitUserProcess are deliberately
                // LEFT CLEAN here -- PatchThread's InitExitHooks() MinHooks them
                // for full caller-stack logging and needs an unmodified prologue.
                // kernel32 exit stubs above still get the early EB-FE guard.
                (void)hNt;
                // Install VEH inline too -- HW BP needs it ready before the
                // first DR0 hit. AddVectoredExceptionHandler is just a
                // linked-list insertion, doesn't take loader lock.
                g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
                Log(g_vehHandle ? "[inline] VEH installed" : "[inline] VEH FAILED");
            }
        } else {
            Log("[launcher] ScyllaHide / inline patches / VEH SKIPPED");
        }

        HANDLE h = CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
        // Background dialog dismisser -- sadece STUB MODE (launcher/payload observer'da yok)
        if (!IS_OBSERVER_MODE()) {
            HANDLE hDk = CreateThread(NULL, 0, DialogKillerThread, NULL, 0, NULL);
            if (hDk) CloseHandle(hDk);
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        Log("DLL_PROCESS_DETACH");
        if (g_vehHandle) RemoveVectoredExceptionHandler(g_vehHandle);
    }
    return TRUE;
}


