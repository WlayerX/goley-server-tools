// revival_patcher.dll
//
// Goley_.exe'ye inject edilen ana DLL. Themida packer'ini ve nProtect
// anti-cheat'i atlatmaktan sorumlu.
//
// Strateji ozeti:
//   - Themida hafiza uzerinde patch yapilmasini hash check ile yakaliyor.
//     Bu yuzden binary'e hicbir zaman dokunmuyoruz. Onun yerine donanim
//     breakpoint (DR0) ile validation branch'ini yakalayip VEH icinde
//     EIP'yi yeniden yaziyoruz. Memory degismedi, hash check gecer.
//   - Process'i olduren API'leri (TerminateProcess, ExitProcess, ntdll
//     muadilleri) DllMain icinde inline patch'liyoruz. Boylece Themida
//     unpack basladiginda zaten silah'lanmis durumdayiz, yarisi mimari
//     olarak kaybetmemis oluyoruz. Detay: docs/THEMIDA_BYPASS.md
//   - nProtect'in MessageBox dialog'larini IAT hijack + HW BP ile
//     bastiriyoruz.

// winsock2.h MUTLAKA windows.h'tan ONCE include edilmeli.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

// MinHook: kernel32!CreateProcessA ve CreateProcessW hook'lari icin.
// nProtect "trusted re-launch" pattern'i ile Goley_'i tekrar spawn
// edebiliyor; bu hook'lar sayesinde child process'lere de DLL inject
// edebiliyoruz. MinHook (BSD) build.bat icinde bu DLL'e statik olarak
// dahil ediliyor (hde32 + trampoline + buffer modulleri).
#include "MinHook.h"

// HDE32: minhook icindeki Hacker Disassembler Engine. Tek bir x86
// instruction'un uzunlugunu olcer. AV swallow'da EIP'yi dogru atlamak
// icin kullaniyoruz. C linkajli, extern "C" sariyoruz.
extern "C" {
#include "hde/hde32.h"
}

// DLL'in disk uzerindeki yolu. DllMain icinde GetModuleFileNameA ile
// hesaplaniyor. Child process'lere kendimizi inject ederken bu yolu
// kullaniyoruz (LoadLibraryA target process'te bizim DLL'i bulsun diye).
static char SELF_DLL_PATH[MAX_PATH] = {0};

// Validation function entry point (image base 0x400000 + RVA 0x93dc4d = 0xD3DC4D)
// This is `cmp byte [esp+13h], 0`:entry of the validation fail path.
// We want to skip this entire path, jumping to success_path = 0xD3DCF2.
//
// Pattern at 0xD3DC4D: 80 7C 24 13 00 0F 85 94 00 00 00 ...
// Instead of patching, we break before execution and rewrite EIP.

static const DWORD VALIDATION_RVA = 0x93DC4D;
static const DWORD SUCCESS_RVA    = 0x93DCF2;  // target jmp destination

// GameGuard CHECK result handler. Originally we tried to skip `call 0x8e3550`
// entirely (PRIMARY_RVA = 0x935374), but the function has side effects --
// internal GG state flags that downstream code relies on. Skipping it
// triggered an immediate (~1 sec) suicide.
//
// New strategy: let the call EXECUTE (preserves side effects), then HW BP
// at the instruction RIGHT AFTER the call (`mov esi, eax` at 0xD35379).
// We force EAX = 0x755 just before the move, so esi gets the magic
// "all clear" value -- the je at 0xD35381 then routes into success path.
static const DWORD GG_RESULT_PATCH_RVA = 0x935379;  // 0xD35379 (mov esi, eax)
static const DWORD GG_OK_STATUS        = 0x755;

// Parent's CreateProcessA call site that spawns the "trusted" child Goley_.
// At 0xD35586/etc. happens; THIS specific site is the re-exec call.
// Static disasm showed call [0x199854C] sites at 0x8DE91A/0x8E5015/0x8E5A19/0x8EA21B.
// 0x8E5A19 is the most likely re-exec (pushes 0x12b1d48 = exe path).
//
// On HW BP hit at the CALL: read dwCreationFlags from stack (6th __stdcall arg),
// OR-in CREATE_SUSPENDED (0x4) so the child spawns frozen. PowerShell watcher
// then injects + resumes -- this is the only way to beat Themida's anti-inject
// timing window in the child.
static const DWORD GG_CREATEPROC_CALL_RVA = 0x4E5A19;  // 0x8E5A19 - 0x400000

// Old MessageBoxW CALL skip (kept as fallback / additional intercept)
static const DWORD GG_MBW_CALL_RVA      = 0x935586;
static const DWORD GG_MBW_CALL_NEXT_RVA = 0x93558B;

// IAT slot kept for diagnostics (it's MEM_FREE at runtime due to Themida obfuscation)
static const DWORD GOLEY_MBW_IAT_VA = 0x019984D4;

// GameGuard error 153 dialog comes from nProtect's own DLL (decrypted from
// npggNT.des at runtime) calling user32!MessageBoxW directly -- NOT from
// Goley_'s ShowGameGuardError function (which we found earlier handles
// error codes 1001-1018 only). So we hook MessageBoxW/MessageBoxA at the
// user32 export entry. On HW BP hit at the FIRST instruction of these
// functions: return IDOK (1) without showing any dialog.
//
// __stdcall MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT) -- 4 args, 16 bytes
// On entry: [esp] = return addr, [esp+4..esp+16] = args
// We restore ESP and EIP as if "ret 16" had executed.
static BYTE* g_imageBase = NULL;
// LAUNCHER MODE: Goley.exe (launcher) Themida'siz; VEH AV swallow loop'u
// onun normal exception'larini yutarak crash'a yol aciyor. Bu flag DllMain
// process exe adina bakarak set ediliyor. true ise VEH AV path'i ihmal eder
// ve OS handler'a birakir.
static volatile LONG g_launcherMode = 0;
// PAYLOAD MODE: BinaryTr.bin (gercek game payload). Phase 1 = minimal
// observer -- hicbir inline patch / VEH / fake cmdline / ScyllaHide yok.
// Sadece network + window audit + module snapshot + raw cmdline log.
// Crash 0xC0000005'i once observe et, sonra kademeli hook ekle.
static volatile LONG g_payloadMode = 0;
// passive observer mode: launcher VEYA payload. Armor skip condition.
#define IS_OBSERVER_MODE() (g_launcherMode || g_payloadMode)
static PVOID g_vehHandle = NULL;
static DWORD g_msgBoxAVA = 0;                   // resolved at PatchThread start
static DWORD g_msgBoxWVA = 0;
static volatile LONG g_valHit = 0;             // validation bypass hit
static volatile LONG g_mbaHit = 0;             // MessageBoxA suppression hit count
static volatile LONG g_mbwHit = 0;             // MessageBoxW suppression hit count
static volatile LONG g_ggrHit = 0;             // GG result patch hit (one-shot)
static volatile LONG g_cpHit  = 0;             // CreateProcess call patched flag (one-shot)
static DWORD g_createProcessWVA = 0;            // resolved at PatchThread start

// Log dosyasinin yolu. DllMain'de hesaplanir: bu DLL'in bulundugu
// klasor + "..\\..\\patcher.log" (yani repo'nun kokune).
static char g_logPath[MAX_PATH] = {0};
static HANDLE g_conHandle = INVALID_HANDLE_VALUE;  // anlik gozlem icin konsol

// Goley_ SUBSYSTEM:WINDOWS oldugu icin process'in console'u yok.
// AllocConsole ile yeni bir konsol penceresi ac, stdout'u oraya bagla.
// Log() hem konsola hem dosyaya basacak -- ikisini de bir arada al.
static void InitDebugConsole() {
    if (g_conHandle != INVALID_HANDLE_VALUE) return;  // zaten kurulu
    if (!AllocConsole()) {
        // Bazi durumlarda (parent zaten console-attach'li ise) AttachConsole'a dus
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
    }
    g_conHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_conHandle == INVALID_HANDLE_VALUE) return;
    char title[128];
    wsprintfA(title, "revival_patcher.dll - LIVE LOG  [PID=%lu]", GetCurrentProcessId());
    SetConsoleTitleA(title);
    // QuickEdit mode kapali olsun -- aksi halde kullanici text secince
    // konsol pause olur, patcher'in stdout write'i blokken Goley_ donar.
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hIn, &mode)) {
            mode &= ~0x0040;  // ENABLE_QUICK_EDIT_MODE
            mode |=  0x0080;  // ENABLE_EXTENDED_FLAGS
            SetConsoleMode(hIn, mode);
        }
    }
}

static void Log(const char* msg) {
    char timed[1100];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int n = wsprintfA(timed, "[%02d:%02d:%02d.%03d P=%lu] %s\r\n",
                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                      GetCurrentProcessId(), msg);

    // 1) Konsola anlik bas (kullanici akar gibi gorur)
    if (g_conHandle != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(g_conHandle, timed, n, &w, NULL);
    }

    // 2) Dosyaya da yaz (gecmis bilgi)
    // Eger Log() DllMain'den once cagrilirsa, fallback olarak
    // %TEMP%\patcher.log'a yaz.
    const char* path = g_logPath[0] ? g_logPath : "patcher.log";
    HANDLE h = CreateFileA(path,
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(h, timed, n, &written, NULL);
        CloseHandle(h);
    }
}

// VEH handler:gets called whenever ANY exception fires in the process.
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS exc) {
    DWORD code = exc->ExceptionRecord->ExceptionCode;
    DWORD eip = exc->ContextRecord->Eip;

    // Themida anti-debug fingerprint: ntdll-level INT3 (0xCC) sprinkled
    // through unpacker. With a debugger attached, the debugger consumes
    // these and Themida sees "debugger present -> abort". With NO
    // debugger and NO VEH, they go to OS UnhandledExceptionFilter -> die.
    // We swallow them: skip past the 0xCC byte (EIP+1) and continue --
    // same effect as a debugger that quietly absorbs them.
    if (code == EXCEPTION_BREAKPOINT &&
        eip >= 0x77000000 && eip < 0x78000000) {  // ntdll range (32-bit ASLR)
        exc->ContextRecord->Eip = eip + 1;
        // No log here -- can fire hundreds of times; would flood the log.
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Themida voluntary AV swallow. Themida unpacker'in kasitli AV
    // pattern'leri var, hepsini "debugger var mi" testi olarak
    // kullaniyor. Yutmazsak OS UnhandledExceptionFilter -> process oluyor.
    // Iki ayri durum yakaliyoruz:
    //
    //   (a) EIP gecerli, instruction icinde AV (write-to-bad-addr vs.)
    //       -> HDE32 ile instruction uzunlugunu olc, EIP'yi advance et.
    //
    //   (b) EIP=0 veya EIP=0xFFFFFFFF (Themida stack corruption).
    //       Themida bilerek ret-to-FFFFFFFF yapiyor. Stack'in tepesindeki
    //       donus adresini EIP'ye al, ESP'yi 4 ilerlet, "ret"i manuel
    //       simule et.
    //
    // Gercek crash AV'lerini de yutma riski var, ama Goley_ zaten oluyor;
    // daha kotusu yok. Eger gercek bir bug varsa surec asagida cikartir.


    // We installed DR0 hardware breakpoint on validation branch entry.
    // When EIP hits it, Windows fires EXCEPTION_SINGLE_STEP.
    //
    // IMPORTANT: 0xD3DC4D is NOT a function entry -- it is an inline
    // conditional branch INSIDE a larger function. Original code:
    //   D3DC4D: 80 7C 24 13 00       cmp byte [esp+13h], 0
    //   D3DC52: 0F 85 9A 00 00 00    jne 0xD3DCF2     (success_path)
    //   D3DC58: ... fail path ...
    // So we must NOT pop the stack or fake-return. We jump directly to
    // the success branch (EIP = SUCCESS_RVA). Stack stays intact, EAX
    // untouched. Semantically identical to "patch jne -> jmp" but
    // without modifying memory (Themida hash check stays happy).
    if (code == EXCEPTION_SINGLE_STEP) {
        DWORD valVA  = (DWORD)(g_imageBase + VALIDATION_RVA);
        DWORD ggrVA  = (DWORD)(g_imageBase + GG_RESULT_PATCH_RVA);
        DWORD mbwVA  = (DWORD)(g_imageBase + GG_MBW_CALL_RVA);
        DWORD mbwNx  = (DWORD)(g_imageBase + GG_MBW_CALL_NEXT_RVA);

        // -- ntdll!NtCreateUserProcess entry point hook
        //    Lowest-level user-mode syscall stub for process creation. Args:
        //      [esp+0x00] = return addr
        //      [esp+0x04] = ProcessHandle (out)
        //      [esp+0x08] = ThreadHandle (out)
        //      [esp+0x0C] = ProcessDesiredAccess
        //      [esp+0x10] = ThreadDesiredAccess
        //      [esp+0x14] = ProcessObjectAttributes
        //      [esp+0x18] = ThreadObjectAttributes
        //      [esp+0x1C] = ProcessFlags
        //      [esp+0x20] = ThreadFlags     <-- set bit 0 (CREATE_SUSPENDED) here
        //      [esp+0x24] = ProcessParameters
        //      [esp+0x28] = CreateInfo
        //      [esp+0x2C] = AttributeList
        if (g_createProcessWVA && eip == g_createProcessWVA) {
            DWORD* esp = (DWORD*)exc->ContextRecord->Esp;
            DWORD origThreadFlags = esp[8];          // [esp+0x20]
            DWORD newThreadFlags  = origThreadFlags | 0x1;  // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
            esp[8] = newThreadFlags;
            char buf[200];
            wsprintfA(buf, "NtCreateUserProcess hooked @ 0x%X: ThreadFlags 0x%X -> 0x%X caller=0x%X",
                      eip, origThreadFlags, newThreadFlags, esp[0]);
            Log(buf);
            exc->ContextRecord->Dr3  = 0;
            exc->ContextRecord->Dr7 &= ~0x40;
            InterlockedExchange(&g_cpHit, 1);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- GameGuard CHECK RESULT @ 0xD35379 (PRIMARY bypass)
        //    The check function 0x8e3550 has already executed (preserving
        //    side effects). We're now at `mov esi, eax`. Force EAX=0x755
        //    BEFORE the move so esi gets the magic, then cmp/je routes
        //    naturally into the success path.
        if (eip == ggrVA) {
            char buf[160];
            DWORD origEax = exc->ContextRecord->Eax;
            wsprintfA(buf, "GG RESULT patched @ 0x%X: EAX 0x%X -> 0x755",
                      eip, origEax);
            Log(buf);
            exc->ContextRecord->Eax = GG_OK_STATUS;
            exc->ContextRecord->Dr2  = 0;
            exc->ContextRecord->Dr7 &= ~0x10;        // disarm L2
            InterlockedExchange(&g_ggrHit, 1);       // tell refresh loop to stop re-arming DR2
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- MessageBoxW CALL site (GameGuard error 150 dialog)
        // Runtime bytes here: E8 FA B1 11 06 (rel32 call into Themida VM
        // that forwards to user32!MessageBoxW). We skip the entire 5-byte
        // CALL by setting EIP to the next instruction. EAX = IDOK so any
        // caller that expects "user clicked OK" semantics keeps flowing.
        if (eip == mbwVA) {
            char buf[160];
            wsprintfA(buf, "MessageBoxW CALL skipped @ 0x%X -> EIP=0x%X EAX=1 (IDOK)",
                      eip, mbwNx);
            Log(buf);
            exc->ContextRecord->Eax = 1;             // IDOK
            exc->ContextRecord->Eip = mbwNx;         // skip the CALL
            exc->ContextRecord->Dr1  = 0;
            exc->ContextRecord->Dr7 &= ~0x4;         // disarm L1
            InterlockedIncrement(&g_mbwHit);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- Themida validation branch (0xD3DC4D)
        if (eip == valVA) {
            // STRATEGY: Do NOT jump to success_path -- that path expects
            // validation code to have initialized certain registers/memory
            // first, so jumping in mid-stride causes NULL deref @ 0xD3DCF4.
            //
            // Instead, RIG THE INPUT: poke [esp+0x13] = 1 so when
            //   cmp byte [esp+13h], 0   (at this address)
            //   jne 0xD3DCF2            (at +5)
            // executes naturally, cmp sees nonzero, jne is TAKEN, and
            // validation flows into success path with ALL side-effects
            // (register init, etc.) properly performed.
            //
            // Then self-disarm DRx so the cmp itself doesn't re-trigger
            // the breakpoint after we return EXCEPTION_CONTINUE_EXECUTION.
            BYTE* stackByte = (BYTE*)(exc->ContextRecord->Esp + 0x13);
            BYTE  oldVal = *stackByte;
            *stackByte = 1;

            char buf[256];
            wsprintfA(buf, "VEH hit! EIP=0x%X  [esp+13h]: 0x%02X -> 0x01  (let cmp/jne run natural)",
                      eip, oldVal);
            Log(buf);

            // Disarm DR0/L0 in THIS thread so the same instruction doesn't
            // re-fire the BP on every retry. The refresh loop will see
            // g_valHit=1 and stop arming new threads.
            exc->ContextRecord->Dr0  = 0;
            exc->ContextRecord->Dr7 &= ~0x1;         // clear L0 only (keep L1/L2)

            // Don't touch EIP -- let the cmp/jne execute normally.
            InterlockedExchange(&g_valHit, 1);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Themida's VM dispatcher fires THOUSANDS of STATUS_PRIVILEGED_INSTRUCTION
    // (0xC0000096) exceptions per second emulating cpuid/rdtsc/etc. Logging
    // each one is so slow that Themida's own VEH chain gets starved and the
    // process can't finish unpacking. So filter to "interesting" codes only:
    //   - ACCESS_VIOLATION  (0xC0000005) -- could indicate Themida's tamper kill
    //   - INVALID_HANDLE    (0xC0000008)
    //   - STACK_OVERFLOW    (0xC00000FD)
    //   - INTEGER_DIVIDE    (0xC0000094)
    //   - BREAKPOINT        (0x80000003)
    //   - ILLEGAL_INSTRUCTION(0xC000001D)
    if (code == EXCEPTION_ACCESS_VIOLATION   ||
        code == 0xC0000008 /* INVALID_HANDLE */ ||
        code == EXCEPTION_STACK_OVERFLOW     ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
        code == EXCEPTION_BREAKPOINT         ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        // Filter out our OWN IAT probe -- when Themida hasn't mapped the
        // import page yet, our `*(DWORD*)GOLEY_MBW_IAT_VA` read access-faults.
        // VirtualQuery pre-check is in place but defense-in-depth: also ignore
        // the AV when fault address matches our IAT slot exactly.
        DWORD faultAddr = exc->ExceptionRecord->NumberParameters > 1
                          ? (DWORD)exc->ExceptionRecord->ExceptionInformation[1] : 0;
        if (code == EXCEPTION_ACCESS_VIOLATION && faultAddr == GOLEY_MBW_IAT_VA) {
            return EXCEPTION_CONTINUE_SEARCH;  // silent
        }

        // AV-rescue RE-ENABLED for the IFEO-wrapper setup. Previously
        // this triggered a self-re-exec path that hid the window, but
        // now wrapper.exe catches the re-exec via IFEO and injects our
        // DLL into the child too -- so going down the re-exec branch
        // is fine, the child carries our bypass.
        static const wchar_t g_emptyWStr[2] = { 0, 0 };
        if (code == EXCEPTION_ACCESS_VIOLATION &&
            eip == 0xD30313 && faultAddr == 0) {
            exc->ContextRecord->Edx = (DWORD)(ULONG_PTR)&g_emptyWStr[0];
            char buf[160];
            wsprintfA(buf, "AV @ 0xD30313 [edx]=NULL -> EDX=0x%p (empty wstring)",
                      &g_emptyWStr[0]);
            Log(buf);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // STATUS_ILLEGAL_INSTRUCTION (0xC000001D) Themida'nin tamper-detection
        // flood'u. Log spam'i CPU yer. Sadece ilk 5'i logla, gerisi sessiz.
        static volatile LONG g_illegalCount = 0;
        BOOL doLog = TRUE;
        if (code == 0xC000001D) {
            LONG c = InterlockedIncrement(&g_illegalCount);
            if (c > 5) doLog = FALSE;
            if (c == 6) Log("INTERESTING EXC 0xC000001D flood, log sessizlendi");
        }
        if (doLog) {
            char buf[256];
            wsprintfA(buf, "INTERESTING EXC: code=0x%X EIP=0x%X flags=0x%X p0=0x%X p1=0x%X",
                      code, eip, exc->ExceptionRecord->ExceptionFlags,
                      exc->ExceptionRecord->NumberParameters > 0
                          ? (DWORD)exc->ExceptionRecord->ExceptionInformation[0] : 0,
                      faultAddr);
            Log(buf);
        }

        if (code == EXCEPTION_ACCESS_VIOLATION) {
    // Only rescue/swallow if the crash
    // is in system DLLs (>= 0x70000000 in 32-bit ASLR)
    // or completely invalid (EIP = 0 or
    // 0xFFFFFFFF). This lets Themida's own
    // voluntary AV exceptions flow to
    // its own handlers so it doesn't detect tampering.
    BOOL shouldRescue = (eip >= 0x70000000 || eip == 0 || eip == 0xFFFFFFFF);
    if (shouldRescue) {
        if (eip < 0x1000 || eip > 0xFFFFFFF0) {
            // Stack restoration (simulate RET)
            DWORD* esp = (DWORD*)exc->ContextRecord->Esp;
            __try {
                DWORD retAddr = esp[0];
                exc->ContextRecord->Eip = retAddr;
                exc->ContextRecord->Esp += 4;

                static int avStackCount = 0;
                if (avStackCount < 50) {
                    avStackCount++;
                    char buf[160];
                    wsprintfA(buf, "AV-rescue (invalid EIP 0x%X): simulated RET to 0x%X", eip, retAddr);
                    Log(buf);
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("AV-rescue FAILED: invalid EIP and unreadable stack");
            }
        } else {
            // Instruction length advance via HDE32
            hde32s hs;
            __try {
                unsigned int instLen = hde32_disasm((const void*)eip, &hs);
                if (instLen > 0 && instLen <= 15 && !(hs.flags & F_ERROR)) {
                    exc->ContextRecord->Eip = eip + instLen;
                    
                    static int avSwallowCount = 0;
                    if (avSwallowCount < 100) {
                        avSwallowCount++;
                        char buf[256];
                        wsprintfA(buf, "AV-rescue @ EIP=0x%X (fault=0x%X, write=%d) -> advanced EIP by %u to 0x%X", 
                                  eip, faultAddr, (exc->ExceptionRecord->ExceptionInformation[0] == 1), instLen, eip + instLen);
                        Log(buf);
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                } else {
                    static int avErrCount = 0;
                    if (avErrCount < 20) {
                        avErrCount++;
                        char buf[160];
                        wsprintfA(buf, "AV-rescue FAILED: HDE32 parsing error (len=%u, flags=0x%X)", instLen, hs.flags);
                        Log(buf);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                static int avExCount = 0;
                if (avExCount < 20) {
                    avExCount++;
                    char buf[160];
                    wsprintfA(buf, "AV-rescue FAILED: Exception while disassembling at 0x%X", eip);
                    Log(buf);
                }
            }
        }
    }
}
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Inline-patch a __stdcall(N args) function to: mov eax, 1; ret <retBytes>
// Used to neutralize select user32/kernel32 APIs so the game/anti-cheat
// either fakes-success or silently no-ops. Memory write is on system DLLs,
// NOT on Themida-protected game code, so Themida's hash check stays happy.
//
// 8 bytes overwritten at function entry:
//   B8 01 00 00 00      mov eax, 1     ; success / IDOK / TRUE
//   C2 RR 00 / 90...    ret <retBytes> ; stdcall cleanup
//
// For functions that take N args (4 bytes each), retBytes = N * 4.
// Special case ExitProcess: it normally never returns, but we override that
// by returning (with EAX=0 and ret 4) so the caller continues execution.
static BOOL PatchStdcallStub(DWORD funcVA, int retBytes, const char* name) {
    if (!funcVA) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: %s VA is NULL, skipped", name);
        Log(buf);
        return FALSE;
    }
    BYTE patch[8] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,         // mov eax, 1
        0xC2, (BYTE)(retBytes & 0xFF), 0x00   // ret <retBytes>
    };
    DWORD oldProt = 0;
    LPVOID target = (LPVOID)(ULONG_PTR)funcVA;
    if (!VirtualProtect(target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt)) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: VirtualProtect failed for %s (err=%lu)",
                  name, GetLastError());
        Log(buf);
        return FALSE;
    }
    BYTE orig[8];
    memcpy(orig, target, sizeof(orig));
    memcpy(target, patch, sizeof(patch));

    DWORD dummy;
    VirtualProtect(target, sizeof(patch), oldProt, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(patch));

    char buf[256];
    wsprintfA(buf, "Patched %s @ 0x%X  orig=%02X%02X%02X%02X%02X%02X%02X%02X -> mov eax,1 / ret %d",
              name, funcVA,
              orig[0], orig[1], orig[2], orig[3], orig[4], orig[5], orig[6], orig[7],
              retBytes);
    Log(buf);
    return TRUE;
}

// Backward-compat shim for the existing call sites
static BOOL PatchMessageBoxStub(DWORD funcVA, const char* name) {
    return PatchStdcallStub(funcVA, 16, name);  // 4 args
}

// Fake MessageBoxW that Goley_'s IAT will point at after we hijack the slot.
// Returns IDOK without showing any dialog.
static int WINAPI FakeMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    char tbuf[256] = {0};
    char cbuf[256] = {0};
    // Best-effort log: convert wide -> ANSI for log file (truncate at 255).
    if (lpText) {
        for (int i = 0; i < 255 && lpText[i]; i++) {
            tbuf[i] = (lpText[i] < 0x80) ? (char)lpText[i] : '?';
        }
    }
    if (lpCaption) {
        for (int i = 0; i < 255 && lpCaption[i]; i++) {
            cbuf[i] = (lpCaption[i] < 0x80) ? (char)lpCaption[i] : '?';
        }
    }
    char buf[1024];
    wsprintfA(buf, "FakeMessageBoxW INTERCEPT: caption='%s' text='%s' type=0x%X -> IDOK",
              cbuf, tbuf, uType);
    Log(buf);
    return 1;  // IDOK
}

// Scan process memory for all 4-byte aligned DWORDs that equal `target`,
// optionally overwriting them with `replacement`. Returns count of slots
// found/patched. Themida obfuscates the original IAT, so the only reliable
// way to find function-pointer slots is to scan runtime memory for the
// resolved API address itself.
//
// We deliberately SKIP our own DLL's memory range to avoid breaking our
// own MessageBoxW import (could cause infinite recursion if we ever call
// it from our code).
static int ScanAndReplaceFnPointer(DWORD target, DWORD replacement, const char* name,
                                   BOOL dryRun) {
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = (BYTE*)0x00010000;
    BYTE* endAddr = (BYTE*)0x7FFE0000;  // user-mode upper limit (x86)

    // Compute our own DLL's memory range so we can exclude it
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&ScanAndReplaceFnPointer, &hSelf);
    DWORD selfBase = (DWORD)(ULONG_PTR)hSelf;
    DWORD selfEnd  = selfBase + 0x100000;  // assume <=1MB DLL
    while (addr < endAddr) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x10000;
            continue;
        }
        // Skip free / guard / no-access pages, and skip executable code
        // sections (we only want data sections where IAT slots live).
        BOOL skip = (mbi.State != MEM_COMMIT)
                 || (mbi.Protect & PAGE_NOACCESS)
                 || (mbi.Protect & PAGE_GUARD)
                 // skip pure-executable pages (no read => unlikely IAT)
                 || (mbi.Protect == PAGE_EXECUTE);

        // Also skip our own DLL's memory
        DWORD regionStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
        if (regionStart >= selfBase && regionStart < selfEnd) {
            skip = TRUE;
        }

        if (!skip) {
            DWORD scanStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
            DWORD scanEnd   = scanStart + (DWORD)mbi.RegionSize;
            // Align to 4 bytes
            scanStart = (scanStart + 3) & ~3;
            for (DWORD p = scanStart; p + 4 <= scanEnd; p += 4) {
                __try {
                    if (*(DWORD*)(ULONG_PTR)p == target) {
                        found++;
                        if (!dryRun) {
                            DWORD oldProt;
                            if (VirtualProtect((LPVOID)(ULONG_PTR)p, 4, PAGE_READWRITE, &oldProt)) {
                                *(DWORD*)(ULONG_PTR)p = replacement;
                                DWORD dummy;
                                VirtualProtect((LPVOID)(ULONG_PTR)p, 4, oldProt, &dummy);
                                char buf[160];
                                wsprintfA(buf, "  patched %s slot at 0x%X  prot=0x%X",
                                          name, p, mbi.Protect);
                                Log(buf);
                            }
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    // Page changed mid-scan, skip
                    break;
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    char buf[160];
    wsprintfA(buf, "Memory scan for %s (target=0x%X) found %d slot(s) %s",
              name, target, found, dryRun ? "[dry-run]" : "[patched]");
    Log(buf);
    return found;
}

// Overwrite a DWORD at the given VA. Used to rewrite Goley_'s IAT slot.
static BOOL PatchIATSlot(DWORD slotVA, DWORD newValue, const char* name) {
    DWORD oldProt = 0;
    LPVOID slot = (LPVOID)(ULONG_PTR)slotVA;
    if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &oldProt)) {
        char buf[160];
        wsprintfA(buf, "PatchIATSlot: VirtualProtect failed for %s @ 0x%X (err=%lu)",
                  name, slotVA, GetLastError());
        Log(buf);
        return FALSE;
    }
    DWORD oldVal = *(DWORD*)slot;
    *(DWORD*)slot = newValue;
    DWORD dummy;
    VirtualProtect(slot, sizeof(DWORD), oldProt, &dummy);

    char buf[160];
    wsprintfA(buf, "IAT slot %s @ 0x%X: 0x%X -> 0x%X", name, slotVA, oldVal, newValue);
    Log(buf);
    return TRUE;
}

// Hook ExitProcess + TerminateProcess so we know who's killing us.
// We can't easily call original (which would require trampoline);
// instead we just LOG the call stack and then ABORT the kill by
// suspending the current thread forever -- this keeps the process alive
// long enough to inspect with a debugger.
typedef VOID(WINAPI *ExitProcess_t)(UINT);
typedef BOOL(WINAPI *TerminateProcess_t)(HANDLE, UINT);
static ExitProcess_t g_origExitProcess = NULL;
static TerminateProcess_t g_origTerminateProcess = NULL;

static VOID WINAPI HookedExitProcess(UINT uExitCode) {
    DWORD retAddr = (DWORD)(ULONG_PTR)_ReturnAddress();
    char buf[256];
    wsprintfA(buf, "*** ExitProcess(0x%X) called from caller=0x%X -- SUSPENDING thread ***",
              uExitCode, retAddr);
    Log(buf);
    // Suspend forever -- gives us time to attach debugger / take screenshot
    while (1) { Sleep(60000); }
}

static BOOL WINAPI HookedTerminateProcess(HANDLE hProc, UINT uExitCode) {
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

// Patch IAT of main module to redirect ExitProcess + TerminateProcess.
// Returns count of redirected slots.
static int HookKillApis() {
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

// Enumerate threads in current process and set HW BP on all of them.
// Sets up to 4 simultaneous breakpoints in DR0/DR1/DR2/DR3 (only re-arms
// slots whose corresponding hit-flag is still 0). Pass 0 to skip a slot.
static int SetHardwareBreakpointAllThreads(DWORD t0, DWORD t1, DWORD t2, DWORD t3 = 0) {
    int success = 0;
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("CreateToolhelp32Snapshot failed");
        return 0;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;  // skip our own thread

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                // Build a clean Dr7 with execute-mode 1-byte BPs in DR0/DR1/DR2.
                // Each enabled slot uses RW=00 (execute) LEN=00 (1 byte), so
                // the upper 16 bits of Dr7 stay all-zero. The lower 8 bits
                // hold the L0/G0..L3/G3 enable flags. We enable only Lx for
                // slots whose target is non-zero AND not yet hit.
                DWORD dr7 = 0x00000000;
                if (t0) { ctx.Dr0 = t0; dr7 |= 0x1;  /* L0 */ }
                if (t1) { ctx.Dr1 = t1; dr7 |= 0x4;  /* L1 */ }
                if (t2) { ctx.Dr2 = t2; dr7 |= 0x10; /* L2 */ }
                if (t3) { ctx.Dr3 = t3; dr7 |= 0x40; /* L3 */ }
                else    { ctx.Dr3 = 0; }
                ctx.Dr7 = dr7;
                if (SetThreadContext(hThread, &ctx)) {
                    // Only log every 50th thread set to avoid log spam --
                    // 30+ threads * 20Hz = enormous log volume otherwise.
                    success++;
                }
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return success;
}

// Sweep-clear DR0..DR7 on every thread so Themida's GetThreadContext
// anti-debug probe sees a clean context. Called once after VEH self-disarm.
static int ClearHardwareBreakpointAllThreads() {
    int cleared = 0;
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                ctx.Dr0 = 0;
                ctx.Dr1 = 0;
                ctx.Dr2 = 0;
                ctx.Dr3 = 0;
                ctx.Dr6 = 0;
                ctx.Dr7 = 0;
                if (SetThreadContext(hThread, &ctx)) cleared++;
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return cleared;
}

// ===========================================================================
// Passive thread-EIP polling -- finds the "wait point" without any hooks
// ===========================================================================
//
// Enumerate every thread in this process, SuspendThread + GetThreadContext
// (FULL) + read [ESP] = return address, ResumeThread. Log:
//   - tid
//   - EIP and a hint at which module it's in (kernel32 / kernelbase / ntdll
//     / user32 / image base for Goley_ itself)
//   - ESP and the first DWORD it points at (the wait's return address into
//     the caller's frame).
//
// If a thread is parked in ntdll!NtWaitForSingleObject or kernelbase!
// WaitForSingleObjectEx, its [ESP+0] is the return address we need to
// look up in IDA -- the next instruction after the WaitFor* call inside
// Goley_'s init code. That tells us EXACTLY which wait we have to
// satisfy (by SetEvent on the right handle, or by short-circuiting the
// caller).
//
// This is read-only -- no code is patched, no DRx is touched, no hook is
// installed. nProtect's anti-hook fingerprint check is not tripped.
static DWORD g_lastThreadDumpTick = 0;

static const char* ClassifyEip(DWORD eip) {
    static char buf[64];
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hKernelB = GetModuleHandleA("kernelbase.dll");
    HMODULE hNtdll  = GetModuleHandleA("ntdll.dll");
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    HMODULE hWs2    = GetModuleHandleA("ws2_32.dll");
    HMODULE hImage  = GetModuleHandleA(NULL);

    struct { HMODULE h; const char* tag; DWORD size; } mods[] = {
        { hImage,   "image",     0x02000000 },
        { hNtdll,   "ntdll",     0x00200000 },
        { hKernel,  "kernel32",  0x00200000 },
        { hKernelB, "kernelbase",0x00400000 },
        { hUser32,  "user32",    0x00200000 },
        { hWs2,     "ws2_32",    0x00100000 },
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

static void DumpThreadEips(void) {
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("DumpThreadEips: snapshot FAILED");
        return;
    }

    Log("--- thread EIP dump start ---");

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int total = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;
            if (te.th32ThreadID == currentTid) continue;
            total++;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!hThread) continue;

            DWORD suspendCount = SuspendThread(hThread);

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            BOOL ok = GetThreadContext(hThread, &ctx);

            DWORD retAddr = 0;
            if (ok && ctx.Esp) {
                // Read [ESP+0] = return address (the address right after
                // the call that parked us here, i.e. the next instruction
                // inside the caller -- typically Goley_ code).
                __try {
                    retAddr = *(volatile DWORD*)(ULONG_PTR)ctx.Esp;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    retAddr = 0xDEADBEEF;
                }
            }

            if (ok) {
                char buf[512];
                char eipClass[80]; lstrcpynA(eipClass, ClassifyEip(ctx.Eip), 79); eipClass[79] = 0;
                char retClass[80]; lstrcpynA(retClass, ClassifyEip(retAddr),   79); retClass[79] = 0;
                wsprintfA(buf,
                    "  tid=%lu EIP=0x%08X (%s) ESP=0x%08X [ESP]=0x%08X (%s)",
                    te.th32ThreadID, ctx.Eip, eipClass,
                    ctx.Esp, retAddr, retClass);
                Log(buf);
            } else {
                char buf[160];
                wsprintfA(buf, "  tid=%lu GetThreadContext FAILED err=%lu",
                          te.th32ThreadID, GetLastError());
                Log(buf);
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    char tail[80];
    wsprintfA(tail, "--- thread EIP dump end (%d threads) ---", total);
    Log(tail);
}

// Window dismissal thread: scans for any modal dialog whose caption
// contains "GameGuard" and PostMessages WM_CLOSE to dismiss it without
// touching code memory. nProtect's error dialog is rendered by its own
// decrypted DLL (not Goley_'s code), so neither code-patches nor IAT
// hooks reach it -- only the visible window itself can be intercepted.
typedef struct {
    HWND foundHwnd;
    DWORD ownerPid;
} FindData;

static BOOL CALLBACK FindGGDialogProc(HWND hWnd, LPARAM lParam) {
    FindData* fd = (FindData*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != fd->ownerPid) return TRUE;

    char title[256] = {0};
    GetWindowTextA(hWnd, title, sizeof(title) - 1);
    if (title[0] == '\0') return TRUE;

    // GameGuard error dialogs use captions like:
    //   "GameGuard Error : 150"
    //   "nProtect GameGuard"
    //   "nProtect GameGuard Error Report"
    // Strict filter: only true GameGuard error dialogs by caption.
    // Goley_ main window has title "ChaguChagu V31927 " so we never touch it.
    if (strstr(title, "GameGuard") != NULL ||
        strstr(title, "nProtect")  != NULL) {
        fd->foundHwnd = hWnd;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI DialogKillerThread(LPVOID) {
    DWORD myPid = GetCurrentProcessId();
    int killed = 0;
    while (1) {
        FindData fd = { NULL, myPid };
        EnumWindows(FindGGDialogProc, (LPARAM)&fd);
        if (fd.foundHwnd) {
            char title[256] = {0};
            GetWindowTextA(fd.foundHwnd, title, sizeof(title) - 1);
            char buf[512];
            wsprintfA(buf, "DialogKiller: dismissing hWnd=0x%p title='%s'",
                      fd.foundHwnd, title);
            Log(buf);
            // PostMessage WM_CLOSE is the gentlest dismissal -- equivalent
            // to clicking the X button. Most modal dialogs return IDCANCEL.
            PostMessageA(fd.foundHwnd, WM_CLOSE, 0, 0);
            killed++;
            if (killed > 50) {
                // Safety: if we've killed 50 dialogs, the loop is probably
                // misbehaving (catching the main game window). Stop.
                Log("DialogKiller: too many dismissals, stopping");
                break;
            }
        }
        Sleep(150);  // poll 6-7 Hz
    }
    return 0;
}

// ============================================================================
// MinHook: kernel32!CreateProcessA hook + child APC injection
// ============================================================================
//
// nProtect's NPGameLib.c (reversed source from fatrolls/nProtect-GameGuard)
// shows the parent process calls:
//   CreateProcessA(szGameMon, CommandLine, ..., CREATE_SUSPENDED, ...)
//   <pipe setup>
//   ResumeThread(ProcessInformation.hThread)
//
// To inject our DLL into the child WITHOUT the
// STATUS_PROCESS_IS_TERMINATING race that CreateRemoteThread suffered,
// we hook CreateProcessA inside the parent and queue an APC (asynchronous
// procedure call) on the child's main thread *while it is suspended*.
// When the parent later calls ResumeThread, the very first user-mode code
// the child executes is `LoadLibraryA(<our_dll>)` queued by us.

typedef BOOL (WINAPI *CreateProcessA_t)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessW_t)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static CreateProcessA_t g_origCreateProcessA = NULL;
static CreateProcessW_t g_origCreateProcessW = NULL;

// Inject SELF_DLL_PATH into the child via APC. The child's main thread is
// expected to be in suspended state (created with CREATE_SUSPENDED or
// equivalent). Returns TRUE if QueueUserAPC succeeded.
static BOOL ApcInjectChild(HANDLE hProcess, HANDLE hThread, DWORD childPid) {
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

// Path basename'i ASCII olarak doner. NULL ise "".
static void GetBasenameA(const char* path, char* outBase, int outLen) {
    outBase[0] = 0;
    if (!path) return;
    const char* base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    lstrcpynA(outBase, base, outLen);
}
static void GetBasenameW(LPCWSTR path, char* outBase, int outLen) {
    outBase[0] = 0;
    if (!path) return;
    char asc[280] = {0};
    for (int i = 0; i < 279 && path[i]; i++)
        asc[i] = (path[i] < 0x80) ? (char)path[i] : '?';
    GetBasenameA(asc, outBase, outLen);
}
// Hem app hem cmd'den basename cikar (lpApplicationName NULL ise cmdline'in
// ilk token'i basename'idir). Goley_.exe child'i tanima icin gerekli.
static void ResolveChildBasenameA(const char* lpApp, const char* lpCmd,
                                  char* outBase, int outLen) {
    if (lpApp) { GetBasenameA(lpApp, outBase, outLen); return; }
    if (!lpCmd) { outBase[0] = 0; return; }
    // cmdline'in ilk arg: belki tirnak icinde, belki bosluga kadar
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
static void ResolveChildBasenameW(LPCWSTR lpApp, LPCWSTR lpCmd,
                                  char* outBase, int outLen) {
    if (lpApp) { GetBasenameW(lpApp, outBase, outLen); return; }
    if (!lpCmd) { outBase[0] = 0; return; }
    char ascCmd[280] = {0};
    for (int i = 0; i < 279 && lpCmd[i]; i++)
        ascCmd[i] = (lpCmd[i] < 0x80) ? (char)lpCmd[i] : '?';
    ResolveChildBasenameA(NULL, ascCmd, outBase, outLen);
}

static BOOL WINAPI HookedCreateProcessA(
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

// Wide-char variant. nProtect uses A, but other DLLs in the same process
// (e.g. CRT spawn helpers, system services) may use W. Hook both for safety.
static BOOL WINAPI HookedCreateProcessW(
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

    ApcInjectChild(hProcess, hThread, childPid);

    if (addedSuspend) {
        DWORD prev = ResumeThread(hThread);
        wsprintfA(buf, "  -> manual ResumeThread (prev suspend count=%lu)", prev);
        Log(buf);
    }
    return ok;
}

// ============================================================================
// Wait API hooks:diagnose what handle Goley_'s init thread is blocked on
// ============================================================================
//
// After Themida unpack + GG bypass, Goley_ hangs on "초기화중" (Initializing).
// nProtect normally fires a named event (e.g. "Global\NPGGuard_xxx") when
// GameMon is ready, but we blocked GameMon spawn so the event is never set.
//
// We hook the wait APIs and log -- via NtQueryObject -- the Object Manager
// name of any handle Goley_ blocks on for >= 5 seconds or INFINITE. From
// that we identify the "GameMon ready" event and can `SetEvent` it ourselves.

typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef DWORD (WINAPI *WaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
typedef DWORD (WINAPI *WaitForMultipleObjects_t)(DWORD, const HANDLE*, BOOL, DWORD);
typedef LONG  (NTAPI  *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG  (NTAPI  *NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static WaitForSingleObject_t      g_origWFSO   = NULL;
static WaitForSingleObjectEx_t    g_origWFSOEx = NULL;
static WaitForMultipleObjects_t   g_origWFMO   = NULL;
static NtWaitForSingleObject_t    g_origNtWFSO = NULL;
static NtQueryObject_t            g_pNtQueryObject = NULL;

// Recursion guard so Log()'s internal CreateFile/WriteFile (which may use
// kernel mutexes -> WaitForSingleObject) doesn't re-enter our wait hooks.
// __declspec(thread) was tried but caused early Themida-process death,
// likely due to static TLS section conflicting with packer assumptions.
// We use a single process-wide flag plus InterlockedCompareExchange so
// only one thread logs a wait at a time; the cost is missing a few
// concurrent waits, which is fine for diagnostics.
static volatile LONG g_inHook = 0;
static inline BOOL EnterHook(void) {
    return InterlockedCompareExchange(&g_inHook, 1, 0) == 0;
}
static inline void LeaveHook(void) {
    InterlockedExchange(&g_inHook, 0);
}

// UNICODE_STRING + OBJECT_NAME_INFORMATION layout (private to ntdll headers,
// redeclared here so we don't drag in winternl.h).
typedef struct {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING_local;
typedef struct {
    UNICODE_STRING_local Name;
} OBJECT_NAME_INFORMATION_local;

// Convert kernel handle -> human-readable Object Manager name into `buf`.
// Examples seen in the wild: "\BaseNamedObjects\NPGGuard_xxx",
// "\KernelObjects\HighMemoryCondition", "" (anonymous), etc.
static void DescribeHandle(HANDLE h, char* buf, int bufSize) {
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

static DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout) {
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

static DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout,
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

static DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount,
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

// NtWaitForSingleObject hook removed -- ntdll syscall stubs are too small
// for HDE32 to trampoline reliably. kernel32 wrappers cover what we need.

// --------------------------------------------------------------------
// NMRunParamDLL_SetParam(N) hooks  (launcher param-passing izleme)
// --------------------------------------------------------------------
// Goley.exe (launcher) NMRunParamDLL.dll'i yukleyip SetParam(key, value)
// ile session/auth bilgilerini Registry'ye yaziyor. Sonra RunProgram ile
// Goley_.exe'yi spawn ediyor; child de ayni param store'u okuyor.
//
// Biz Goley_'i dogrudan ate$leyince child Load'da bos store goruyor ve
// 3.3 sn'de exit ediyor. Bu hook her SetParam(key, value) cagrisini
// patcher.log'a yazar -- boylece tum (key, value) tablosunu yakalariz,
// emulator side bunu replicate edip Goley_'i tek basina ya$atabiliriz.
typedef int (__cdecl *NMRunParamSetParam_t)(void* hData, const char* key, const char* value);
typedef int (__cdecl *NMRunParamSetParam2_t)(void* hData, int idx, const char* value);
typedef int (__cdecl *NMRunParamCreate_t)(void);
typedef int (__cdecl *NMRunParamRunProg_t)(void* hData, const char* exe, const char* args);
// Asagidaki imzalar Netmarble convention'a gore tahmin: hData (object), key/idx, optional out-buffer.
// PE disasm gore tum NMRunParamDLL export'lari __cdecl. GetParam 3 arg
// aliyor (hData, key, outBuf?); ExistsParam 2; Load 3. Stack frame'i
// bozmamak icin hook'lar AYNI arg sayisini kullanmali. Varargs kullaniyoruz
// ki tahminimizden bagimsiz olalim.
typedef int (__cdecl *NMRunParamLoad_t)(void* hData, int useGlobalShare, int extra);
typedef int (__cdecl *NMRunParamGetParam_t)(void* hData, const char* key, void* outBuf);
typedef int (__cdecl *NMRunParamExistsParam_t)(void* hData, const char* key);
typedef int (__cdecl *NMRunParamGetParamCount_t)(void* hData);

static NMRunParamSetParam_t      g_origNMRunSetParam   = NULL;
static NMRunParamSetParam2_t     g_origNMRunSetParam2  = NULL;
static NMRunParamRunProg_t       g_origNMRunRunProg    = NULL;
static NMRunParamLoad_t          g_origNMRunLoad       = NULL;
static NMRunParamGetParam_t      g_origNMRunGetParam   = NULL;
static NMRunParamExistsParam_t   g_origNMRunExistsParam= NULL;
static NMRunParamGetParamCount_t g_origNMRunGetCount   = NULL;
static volatile LONG g_nmrunSetParamHits = 0;
static volatile LONG g_nmrunGetParamHits = 0;

// Sahte param store -- gerçek Goley.exe launcher'in Registry'ye yazacaği
// degerlerin yerine bizim sabit string'lerimizi kullaniyoruz. Bu sayede
// Goley_ NMRunParamDLL_Load fail'a ragmen gercek server'a connect olmayi
// dener (bizim emulator'a).
struct FakeParam { const char* key; const char* value; };
static const FakeParam g_fakeParams[] = {
    { "USER_ID",      "goley_test" },
    { "USER_PW",      "test_pw_12345" },
    { "USERID",       "goley_test" },
    { "USERPW",       "test_pw_12345" },
    { "SERVER_IP",    "127.0.0.1" },
    { "SERVERIP",     "127.0.0.1" },
    { "ENTRY_IP",     "127.0.0.1" },
    { "LOGIN_IP",     "127.0.0.1" },
    { "SERVICE",      "1" },
    { "ServiceID",    "1" },
    { "OverrideLanguage", "tr" },
    { "OverrideLangua",   "tr" },
    { "LangCode",     "tr" },
    { "Region",       "TR" },
    { "GameCode",     "Goley" },
    { "session",      "fake_session_token_abc123" },
    { "Session",      "fake_session_token_abc123" },
    { "Token",        "fake_session_token_abc123" },
    { "AuthToken",    "fake_session_token_abc123" },
    { NULL, NULL }
};

static const char* FindFakeParam(const char* key) {
    if (!key) return NULL;
    for (int i = 0; g_fakeParams[i].key; i++) {
        // Case-insensitive compare
        if (lstrcmpiA(key, g_fakeParams[i].key) == 0) {
            return g_fakeParams[i].value;
        }
    }
    return NULL;
}

static int __cdecl HookedNMRunSetParam(void* hData, const char* key, const char* value) {
    InterlockedIncrement(&g_nmrunSetParamHits);
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.SetParam #%ld hData=0x%p key='%.80s' value='%.400s'",
                  g_nmrunSetParamHits, hData,
                  key ? key : "<null>", value ? value : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunSetParam) return g_origNMRunSetParam(hData, key, value);
    return 0;
}

static int __cdecl HookedNMRunSetParam2(void* hData, int idx, const char* value) {
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.SetParam2 hData=0x%p idx=%d value='%.400s'",
                  hData, idx, value ? value : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunSetParam2) return g_origNMRunSetParam2(hData, idx, value);
    return 0;
}

// NMRunParam_Load -- TEST: Load orig'e forward; eger orig fail dönerse, biz
// CreateData + SetParam ile yeni bir hData yarat ve param'lari dolduralim.
// Bu sayede sub_8E23E0 (Goley_'in GetParam wrapper'i) GERCEK hData ile
// calisir, crash olmaz, fake param'lari okuyabilir.
static void* g_fakeHData = NULL;  // bizim onceden hazirlanmiş hData
static int __cdecl HookedNMRunLoad(void* hData, int flag, int extra) {
    int rc = 1;  // assume fail
    if (g_origNMRunLoad) rc = g_origNMRunLoad(hData, flag, extra);
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "NMRun.Load(hData=0x%p, flag=%d) -> orig=%d", hData, flag, rc);
        Log(buf);
        LeaveHook();
    }
    // Eger orig fail donduyse: Goley_'in hData'sini bizim onceden
    // yarattigimiz fake-populated hData ile DEGISTIR. Bunun icin caller
    // genelde "out param" donmuyor (cdecl, hData zaten passed-in). hData
    // pointer iyse, biz oraya OUR hData'nin BYTE'larini overlay etmeliyiz.
    // Bu cok riskli; simdilik sadece return value'yu 0 (success) yap ve
    // umalim ki Goley_ "success" branch'inda KULLANDIGI hData zaten OK.
    if (rc != 0 && g_fakeHData) {
        if (EnterHook()) {
            char b[200];
            wsprintfA(b, "  Load fail, fake hData'yi kullanmak icin force 0 ret");
            Log(b);
            LeaveHook();
        }
        // hData içeriğini bizim fake-state ile overlay (deneysel; eger crash
        // verirse orig fail durumuna düş)
        return 1;  // forward orig fail -- guvenli yol
    }
    return rc;
}

// NMRunParam_GetParam -- LOG-only, orig'e forward. Goley_'in cagirdigi
// her key'i kayda alacagiz, sonra bilerek arg sayisina gore fake yapariz.
// imza: __cdecl GetParam(hData, key, outBuf). outBuf ihtimal char*.
static int __cdecl HookedNMRunGetParam(void* hData, const char* key, void* outBuf) {
    LONG hits = InterlockedIncrement(&g_nmrunGetParamHits);
    if (hits <= 50 && EnterHook()) {
        char buf[400];
        wsprintfA(buf, "NMRun.GetParam #%ld(hData=0x%p, key='%.80s', outBuf=0x%p)",
                  hits, hData, key ? key : "<null>", outBuf);
        Log(buf);
        LeaveHook();
    }
    int rc = 0;
    if (g_origNMRunGetParam) rc = g_origNMRunGetParam(hData, key, outBuf);
    // Bizim fake string'i outBuf'a yaz (eger orig fail dondurduyse)
    const char* fake = FindFakeParam(key);
    if (fake && outBuf && rc != 0) {
        // outBuf char* mı pointer-to-char*-pointer mı belirsiz; ikisini de
        // dene defansif:
        __try {
            strcpy_s((char*)outBuf, 256, fake);
            if (EnterHook()) {
                char b[200];
                wsprintfA(b, "  -> FAKE wrote '%.60s' to outBuf=0x%p", fake, outBuf);
                Log(b);
                LeaveHook();
            }
            rc = 0;  // success
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // outBuf yazilamaz; orig'in donus degerini birak
        }
    }
    return rc;
}

// NMRunParam_ExistsParam -- log + orig forward. (2 arg cdecl, guvenli)
static int __cdecl HookedNMRunExistsParam(void* hData, const char* key) {
    int rc = 0;
    if (g_origNMRunExistsParam) rc = g_origNMRunExistsParam(hData, key);
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "NMRun.ExistsParam('%.80s') -> %d (orig)", key ? key : "<null>", rc);
        Log(buf);
        LeaveHook();
    }
    // FakeParam tablomuzdaki key'leri "var" olarak gosterelim
    if (rc == 0 && FindFakeParam(key)) return 1;
    return rc;
}

// NMRunParam_GetParamCount -- orig forward, fake'leri sayma
static int __cdecl HookedNMRunGetParamCount(void* hData) {
    int rc = 0;
    if (g_origNMRunGetCount) rc = g_origNMRunGetCount(hData);
    return rc;
}

static int __cdecl HookedNMRunRunProg(void* hData, const char* exe, const char* args) {
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.RunProgram hData=0x%p exe='%.200s' args='%.400s'",
                  hData, exe ? exe : "<null>", args ? args : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunRunProg) return g_origNMRunRunProg(hData, exe, args);
    return 0;
}

// ----------------------------------------------------------------------
// NMRunParam hook'lari -- launcher / game ayri fonksiyonlar.
// ----------------------------------------------------------------------
// LAUNCHER MODE:
//   * Goley.exe (launcher) param YAZAN taraf. Sadece gozlemci hook'lar:
//       NMRunParamDLL_SetParam   (key=val log)
//       NMRunParamDLL_SetParam2  (idx=val log)
//       NMRunParamDLL_RunProgram (exe + args log)
//   * Load/GetParam/ExistsParam/GetParamCount HIC HOOKLANMAZ. Launcher
//     bunlari cagirmaz; cagirsa bile fake mode'a girmemeli (gozlemi kirletir).
//   * NMRunParamDLL.dll ZORLA PRELOAD ETMEYIZ. Launcher dogal yolla yukler.
//     Henuz yuklu degilse FALSE doneriz, sonraki refresh loop tekrar dener.
//
// GAME MODE:
//   * Goley_.exe (game client) param OKUYAN taraf. Tum 7 hook + fake mode.
//   * Preload aktif (Themida/launcher yokken bile fake param store burada).

static BOOL InitNMRunParamLauncherHooks() {
    HMODULE hMod = GetModuleHandleA("NMRunParamDLL.dll");
    if (!hMod) return FALSE;  // launcher henuz yuklemedi; tekrar dene
    PVOID p1 = GetProcAddress(hMod, "NMRunParamDLL_SetParam");
    PVOID p2 = GetProcAddress(hMod, "NMRunParamDLL_SetParam2");
    PVOID p3 = GetProcAddress(hMod, "NMRunParamDLL_RunProgram");
    char buf[256];
    wsprintfA(buf, "NMRun launcher targets: SetParam=0x%p SetParam2=0x%p RunProgram=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedNMRunSetParam,
                                    (LPVOID*)&g_origNMRunSetParam);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("  SetParam ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedNMRunSetParam2,
                                    (LPVOID*)&g_origNMRunSetParam2);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("  SetParam2 ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedNMRunRunProg,
                                    (LPVOID*)&g_origNMRunRunProg);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("  RunProgram ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (anyOk) Log("(Launcher mode -- Load/GetParam fake yok)");
    return anyOk;
}

static BOOL InitNMRunParamGameHooks() {
    HMODULE hMod = GetModuleHandleA("NMRunParamDLL.dll");
    if (!hMod) {
        // Game client'da Themida launcher'siz spawn icin fake param store
        // gerek. Bu game-only davranis.
        hMod = LoadLibraryA("C:\\Joygame\\Goley\\BinaryTr\\NMRunParamDLL.dll");
        if (hMod) Log("NMRunParamDLL pre-loaded by patcher (game mode)");
        else      Log("NMRunParamDLL.dll bulunamadi");
        if (!hMod) return FALSE;
    }
    PVOID p1 = GetProcAddress(hMod, "NMRunParamDLL_SetParam");
    PVOID p2 = GetProcAddress(hMod, "NMRunParamDLL_SetParam2");
    PVOID p3 = GetProcAddress(hMod, "NMRunParamDLL_RunProgram");
    PVOID p4 = GetProcAddress(hMod, "NMRunParamDLL_Load");
    PVOID p5 = GetProcAddress(hMod, "NMRunParamDLL_GetParam");
    PVOID p6 = GetProcAddress(hMod, "NMRunParamDLL_ExistsParam");
    PVOID p7 = GetProcAddress(hMod, "NMRunParamDLL_GetParamCount");
    char buf[400];
    wsprintfA(buf, "NMRun game targets: SetParam=0x%p SetParam2=0x%p RunProgram=0x%p", p1, p2, p3);
    Log(buf);
    wsprintfA(buf, "NMRun game targets: Load=0x%p GetParam=0x%p ExistsParam=0x%p GetParamCount=0x%p",
              p4, p5, p6, p7);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedNMRunSetParam,
                                    (LPVOID*)&g_origNMRunSetParam);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("NMRun.SetParam hook ENABLED"); anyOk = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedNMRunSetParam2,
                                    (LPVOID*)&g_origNMRunSetParam2);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("NMRun.SetParam2 hook ENABLED"); anyOk = TRUE;
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedNMRunRunProg,
                                    (LPVOID*)&g_origNMRunRunProg);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("NMRun.RunProgram hook ENABLED"); anyOk = TRUE;
        }
    }
    struct HSpec { PVOID target; LPVOID detour; LPVOID* orig; const char* name; };
    HSpec specs[] = {
        { p4, (LPVOID)&HookedNMRunLoad,          (LPVOID*)&g_origNMRunLoad,        "NMRun.Load" },
        { p5, (LPVOID)&HookedNMRunGetParam,      (LPVOID*)&g_origNMRunGetParam,    "NMRun.GetParam" },
        { p6, (LPVOID)&HookedNMRunExistsParam,   (LPVOID*)&g_origNMRunExistsParam, "NMRun.ExistsParam" },
        { p7, (LPVOID)&HookedNMRunGetParamCount, (LPVOID*)&g_origNMRunGetCount,    "NMRun.GetParamCount" },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        if (!specs[i].target) continue;
        MH_STATUS s = MH_CreateHook(specs[i].target, specs[i].detour, specs[i].orig);
        if (s == MH_OK && MH_EnableHook(specs[i].target) == MH_OK) {
            char b[200];
            wsprintfA(b, "%s hook ENABLED (FAKE param mode)", specs[i].name);
            Log(b);
            anyOk = TRUE;
        }
    }
    return anyOk;
}

// --------------------------------------------------------------------
// kernel32 GetCommandLineA/W hooks
// --------------------------------------------------------------------
// Goley_'in WinMain'i lpCmdLine'da "NoPopup" arar; yoksa MessageBoxW
// "Please run Goley.exe" gosterip return 0 (exit) yapar. Argsiz spawn
// edince dialog gozukup ana thread oluyor. GetCommandLine hook'u ile
// sahte "Goley_.exe TrAuth NoPopup" string'i dondururuz. WinMain bu
// stringi gorur, "NoPopup" matched, exit branchini atlar.
typedef LPSTR (WINAPI *GetCommandLineA_t)(void);
typedef LPWSTR (WINAPI *GetCommandLineW_t)(void);

static GetCommandLineA_t g_origGetCommandLineA = NULL;
static GetCommandLineW_t g_origGetCommandLineW = NULL;
static volatile LONG g_gclLogged = 0;
// Sahte command-line. WinMain bunu strncmp ile arar.
// KESIN BULGU: Goley_.exe argv[1]'i KOSULSUZ child exe path olarak
// spawn ediyor (multi-stage launcher pattern). Her fake cmdline'da
// argv[1] doluysa Goley_ kendisini yine spawn eder = sonsuz recursion
// (3944 wrapper instance fork bomb! gercek olay).
//
// Cozum: fake cmdline TEK ARG ("Goley_.exe" sadece, no payload).
// argv[1] yok -> Goley_ child spawn yolundan cikar, normal main path.
static char g_fakeCmdLineA[] = "Goley_.exe";
static wchar_t g_fakeCmdLineW[] = L"Goley_.exe";

static LPSTR WINAPI HookedGetCommandLineA(void) {
    if (InterlockedExchange(&g_gclLogged, 1) == 0) {
        char buf[200];
        wsprintfA(buf, "GetCommandLineA called -> fake '%s'", g_fakeCmdLineA);
        Log(buf);
    }
    return g_fakeCmdLineA;
}
static LPWSTR WINAPI HookedGetCommandLineW(void) {
    return g_fakeCmdLineW;
}

static BOOL InitCmdLineHooks() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) return FALSE;
    PVOID p1 = GetProcAddress(hKernel, "GetCommandLineA");
    PVOID p2 = GetProcAddress(hKernel, "GetCommandLineW");
    char buf[256];
    wsprintfA(buf, "GetCommandLine targets: A=0x%p W=0x%p", p1, p2);
    Log(buf);
    BOOL ok = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedGetCommandLineA,
                                    (LPVOID*)&g_origGetCommandLineA);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("GetCommandLineA hook ENABLED"); ok = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedGetCommandLineW,
                                    (LPVOID*)&g_origGetCommandLineW);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("GetCommandLineW hook ENABLED"); ok = TRUE;
        }
    }
    return ok;
}

// --------------------------------------------------------------------
// ws2_32 network hooks: connect / gethostbyname / getaddrinfo
// --------------------------------------------------------------------
// Goley_ entry-server'a connect ediyor (TCP 2270) ama bizim emulator'a
// gelmiyor. Hangi hostname/IP'yi cagiriyor bilmek icin connect()'in
// sockaddr'ini ve DNS resolve denemelerini logluyoruz.
// addrinfo struct ws2tcpip.h'de tanimli ama o header Win10 SDK'de
// patolojik (SourceList undeclared). Sadece pointer geciyoruz, forward
// declare yeter.
struct addrinfo_fwd;
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef struct hostent* (WSAAPI *gethostbyname_t)(const char*);
typedef int (WSAAPI *getaddrinfo_t)(const char*, const char*,
                                     const struct addrinfo_fwd*,
                                     struct addrinfo_fwd**);

static connect_t       g_origConnect       = NULL;
static gethostbyname_t g_origGethostbyname = NULL;
static getaddrinfo_t   g_origGetaddrinfo   = NULL;

static int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (EnterHook()) {
        char buf[256];
        if (name && namelen >= 8 && name->sa_family == AF_INET) {
            const struct sockaddr_in* in4 = (const struct sockaddr_in*)name;
            const unsigned char* ip = (const unsigned char*)&in4->sin_addr;
            wsprintfA(buf, "ws2.connect %u.%u.%u.%u:%u",
                      ip[0], ip[1], ip[2], ip[3], ntohs(in4->sin_port));
        } else {
            wsprintfA(buf, "ws2.connect sa_family=%d namelen=%d",
                      name ? name->sa_family : -1, namelen);
        }
        Log(buf);
        LeaveHook();
    }
    return g_origConnect(s, name, namelen);
}

static struct hostent* WSAAPI HookedGethostbyname(const char* name) {
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "ws2.gethostbyname('%.220s')", name ? name : "<null>");
        Log(buf);
        LeaveHook();
    }
    return g_origGethostbyname(name);
}

static int WSAAPI HookedGetaddrinfo(const char* pname, const char* psvc,
                                     const struct addrinfo_fwd* pin,
                                     struct addrinfo_fwd** ppres) {
    if (EnterHook()) {
        char buf[400];
        wsprintfA(buf, "ws2.getaddrinfo('%.220s', '%.32s')",
                  pname ? pname : "<null>", psvc ? psvc : "<null>");
        Log(buf);
        LeaveHook();
    }
    return g_origGetaddrinfo(pname, psvc, pin, ppres);
}

static BOOL InitNetworkHooks() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) return FALSE;
    PVOID p1 = GetProcAddress(hWs2, "connect");
    PVOID p2 = GetProcAddress(hWs2, "gethostbyname");
    PVOID p3 = GetProcAddress(hWs2, "getaddrinfo");
    char buf[256];
    wsprintfA(buf, "Net targets: connect=0x%p gethostbyname=0x%p getaddrinfo=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedConnect,
                                    (LPVOID*)&g_origConnect);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("connect hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "connect hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedGethostbyname,
                                    (LPVOID*)&g_origGethostbyname);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("gethostbyname hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "gethostbyname hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedGetaddrinfo,
                                    (LPVOID*)&g_origGetaddrinfo);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("getaddrinfo hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "getaddrinfo hook FAILED status=%d", s); Log(buf);
        }
    }
    return anyOk;
}

// --------------------------------------------------------------------
// WINDOW AUDIT HOOKS -- evidence-only, no behavior change.
// --------------------------------------------------------------------
// Hedef: 371x143 boyutlu, class adi '#' olan Korece dialog'u KIM
// yaratiyor sorusunu cevaplamak. MessageBoxW/A ve DialogBox* hook'lari
// hic tetiklenmedi, NMRunParam de tetiklenmedi -> dialog standart
// MessageBox cagrisi DEGIL. Bu yuzden bir alt seviyeye iniyoruz:
//
//   * RegisterClassExA/W  -- pencere sinifi adi '#' kayit ediliyor mu?
//                            Hangi hInstance / hangi modul?
//   * CreateWindowExA/W   -- pencere olusturulduktan sonra
//                            (cx,cy)=(371,143) match'i ile detaylı bas.
//                            Caller return address, caller modul, RVA.
//
// Davranis sıfır degisiyor: her hook orig trampoline'a tail-call ediyor.
// Goley_.exe binary'sine tek byte yazilmiyor.
//
// Onemli karar agaci (build sonrasi):
//   - register caller / create caller = nProtect/GameMon/npggNT ise -> H2
//   - register caller / create caller = Goley_ kendisi ise              -> H1
//   - hInstance/caller module resolve etmez (NULL) ise                  -> H3
//   - register eden ile create eden farkli modulse, IKISI DE LOGLANIR.

typedef HWND (WINAPI *CreateWindowExA_t)(DWORD, LPCSTR,  LPCSTR,  DWORD,
                                          int, int, int, int, HWND, HMENU,
                                          HINSTANCE, LPVOID);
typedef HWND (WINAPI *CreateWindowExW_t)(DWORD, LPCWSTR, LPCWSTR, DWORD,
                                          int, int, int, int, HWND, HMENU,
                                          HINSTANCE, LPVOID);
typedef ATOM (WINAPI *RegisterClassExA_t)(const WNDCLASSEXA*);
typedef ATOM (WINAPI *RegisterClassExW_t)(const WNDCLASSEXW*);

static CreateWindowExA_t  g_origCreateWindowExA  = NULL;
static CreateWindowExW_t  g_origCreateWindowExW  = NULL;
static RegisterClassExA_t g_origRegisterClassExA = NULL;
static RegisterClassExW_t g_origRegisterClassExW = NULL;

// Caller address -> module file name resolver. Returns "<anon>" if
// the address falls in private executable memory (no PE module mapped),
// "<unknown>" on outright failure. RVA written into rvaOut if module
// resolved. Buffer is unchanged on failure.
static void ResolveAddrToModule(void* addr, char* outName, int outLen,
                                DWORD* rvaOut) {
    HMODULE hMod = NULL;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &hMod) && hMod) {
        char path[MAX_PATH] = {0};
        if (GetModuleFileNameA(hMod, path, MAX_PATH)) {
            // basename only
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

// Some processes use atom (low-WORD integer) instead of string for
// lpClassName. If the pointer's high WORD is 0 it's an atom; otherwise
// string. We render both as displayable text for the log.
static void RenderClassNameA(LPCSTR cls, char* out, int outLen) {
    if (!cls) { lstrcpynA(out, "<null>", outLen); return; }
    if (((ULONG_PTR)cls) >> 16 == 0) {
        wsprintfA(out, "ATOM(0x%X)", (unsigned)(ULONG_PTR)cls);
    } else {
        // truncate/escape non-printable carefully
        char tmp[80] = {0};
        for (int i = 0; i < 79; i++) {
            char c = cls[i];
            if (c == 0) break;
            tmp[i] = (c >= 32 && c < 127) ? c : '?';
        }
        wsprintfA(out, "'%s'", tmp);
    }
}
static void RenderClassNameW(LPCWSTR cls, char* out, int outLen) {
    if (!cls) { lstrcpynA(out, "<null>", outLen); return; }
    if (((ULONG_PTR)cls) >> 16 == 0) {
        wsprintfA(out, "ATOM(0x%X)", (unsigned)(ULONG_PTR)cls);
    } else {
        // WideChar -> ASCII (lossy) for log
        char asc[80] = {0};
        int n = WideCharToMultiByte(CP_ACP, 0, cls, -1,
                                    asc, sizeof(asc) - 1, NULL, NULL);
        (void)n;
        // mask non-printables
        for (int i = 0; asc[i] && i < 79; i++) {
            if (asc[i] < 32 || asc[i] >= 127) asc[i] = '?';
        }
        wsprintfA(out, "'%s'", asc);
    }
}

// hInstance -> module file name. NULL hInstance is "<exe>" (means main
// module). Unresolvable handle is "<?>".
static void RenderInstanceModule(HINSTANCE hInst, char* out, int outLen) {
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

static ATOM WINAPI HookedRegisterClassExA(const WNDCLASSEXA* lpwcx) {
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

static ATOM WINAPI HookedRegisterClassExW(const WNDCLASSEXW* lpwcx) {
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

// Helper for the create logger -- accepts a window after creation,
// queries its actual size + GCLP_HMODULE so we can correlate against
// what the caller asked for.
static void LogCreateResult(HWND hwnd, const char* api,
                            const char* clsTxt, const char* titleTxt,
                            int reqX, int reqY, int reqW, int reqH,
                            DWORD style, DWORD exStyle,
                            const char* callerMod, DWORD callerRva) {
    // Final size of the window once created (CW_USEDEFAULT resolves
    // here). Important: 371x143 is the OBSERVED size in autopilot2,
    // so we want to match against the post-create RECT, not the
    // requested (cx,cy).
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

    // Extra "this looks like the Korean dialog" log if final dims match.
    // 371x143 is our smoking-gun signature.
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

static HWND WINAPI HookedCreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName,
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

static HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
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

static BOOL InitWindowAuditHooks() {
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

// --------------------------------------------------------------------
// BUGTRAP HOOKS -- 371x143 Korece modal dialog bypass.
// --------------------------------------------------------------------
// Tespit hikayesi:
//   * Onceki autopilot2 + dialog-forensics testleri patcher'siz dialog'un
//     yine cikitigini gosterdi.
//   * dialog-forensics.ps1 cikitisinda dialog class='#32770' (standart
//     user32 DIALOG), GCLP_HMODULE = USER32.dll, ve in-process'te
//     nProtect/GameGuard MODULU YOK.
//   * unpacked_Goley_.exe PE import scan'i: Goley_ DialogBox*/CreateDialog*
//     HIC kullanmiyor; sadece CreateWindowExW (7 call site, hepsi
//     'VLWebWindowClass' icin) + MessageBoxA/W (kullanilmiyor bu yolda).
//   * BugTrap.dll PE import scan'i: DialogBox, CreateDialog, EndDialog,
//     CreateWindowEx, MessageBox HEPSI VAR. Yani 371x143 dialog'u
//     BugTrap.dll DialogBoxParamW cagrisi ile yaratiyor.
//   * Goley_ icindeki call site'lar:
//       BT_SaveSnapshot @ 0xD3669E   -> error snapshot kaydet
//       BT_SendSnapshot @ 0xD366A6   -> snapshot gonder ekrani goster
//       BT_SetFlags     @ 0xD360AA, 0xD36115 (ikinci dal)
//
// Bypass: A + B + C katmanli savunma:
//   A. BT_SaveSnapshot   -> log + return 1 (success), hic snapshot save edilmez
//   B. BT_SendSnapshot   -> log + return 1 (success), dialog hic acilmaz
//   C. BT_SetFlags(any)  -> orig(0) -- BugTrap silent mode

typedef int  (__stdcall *BT_SaveSnapshot_t)(void* excPtrs, const char* fname);
typedef int  (__stdcall *BT_SendSnapshot_t)(void* excPtrs, const char* fname);
typedef void (__stdcall *BT_SetFlags_t)    (DWORD dwFlags);

static BT_SaveSnapshot_t g_origBT_SaveSnapshot = NULL;
static BT_SendSnapshot_t g_origBT_SendSnapshot = NULL;
static BT_SetFlags_t     g_origBT_SetFlags     = NULL;

static int __stdcall HookedBT_SaveSnapshot(void* excPtrs, const char* fname) {
    if (EnterHook()) {
        char buf[320];
        wsprintfA(buf, "BT_SaveSnapshot INTERCEPT exc=0x%p fname='%.220s' -> ret 1",
                  excPtrs, fname ? fname : "<null>");
        Log(buf);
        LeaveHook();
    }
    return 1;  // BugTrap convention: non-zero = success
}

static int __stdcall HookedBT_SendSnapshot(void* excPtrs, const char* fname) {
    if (EnterHook()) {
        char buf[320];
        wsprintfA(buf, "BT_SendSnapshot INTERCEPT exc=0x%p fname='%.220s' -> ret 1",
                  excPtrs, fname ? fname : "<null>");
        Log(buf);
        LeaveHook();
    }
    return 1;
}

static void __stdcall HookedBT_SetFlags(DWORD dwFlags) {
    if (EnterHook()) {
        char buf[120];
        wsprintfA(buf, "BT_SetFlags(0x%X) INTERCEPT -> forcing 0 (silent mode)",
                  dwFlags);
        Log(buf);
        LeaveHook();
    }
    // Original API cagrilir ama her zaman 0 ile -> UI yok, sadece log.
    if (g_origBT_SetFlags) g_origBT_SetFlags(0);
}

static BOOL InitBugTrapHooks() {
    HMODULE hBT = GetModuleHandleA("BugTrap.dll");
    if (!hBT) return FALSE;
    PVOID p1 = GetProcAddress(hBT, "BT_SaveSnapshot");
    PVOID p2 = GetProcAddress(hBT, "BT_SendSnapshot");
    PVOID p3 = GetProcAddress(hBT, "BT_SetFlags");
    char buf[256];
    wsprintfA(buf, "BugTrap targets: Save=0x%p Send=0x%p SetFlags=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedBT_SaveSnapshot,
                                    (LPVOID*)&g_origBT_SaveSnapshot);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("BT_SaveSnapshot hook ENABLED (dialog tetikleyicisi bypass)");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SaveSnapshot hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedBT_SendSnapshot,
                                    (LPVOID*)&g_origBT_SendSnapshot);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("BT_SendSnapshot hook ENABLED");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SendSnapshot hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedBT_SetFlags,
                                    (LPVOID*)&g_origBT_SetFlags);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("BT_SetFlags hook ENABLED (silent mode zorlandi)");
            anyOk = TRUE;
        } else {
            wsprintfA(buf, "BT_SetFlags hook FAILED status=%d", s); Log(buf);
        }
    }
    return anyOk;
}

// One-shot module snapshot. Logs each currently loaded module by
// basename + base address. Looking specifically for npggNT.des,
// GameMon*, npxx*, npggsvc* etc. so we can tell if nProtect is
// in-process or out-of-process.
static void LogLoadedModulesSnapshot(const char* tag) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("LoadedModules: CreateToolhelp32Snapshot failed");
        return;
    }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    char buf[400];
    wsprintfA(buf, "=== loaded modules snapshot (%s) ===", tag);
    Log(buf);
    int count = 0;
    if (Module32First(hSnap, &me)) {
        do {
            wsprintfA(buf, "  mod[%d] base=0x%p size=0x%X %s",
                      count, me.modBaseAddr, me.modBaseSize, me.szModule);
            Log(buf);
            count++;
        } while (Module32Next(hSnap, &me));
    }
    wsprintfA(buf, "=== %d module(s) total ===", count);
    Log(buf);
    CloseHandle(hSnap);
}

// Install Wait* hooks. Called once from PatchThread after MinHook init.
static void InitWaitHooks() {
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

// One-shot MinHook init + enable both CreateProcessA/W hooks. Returns TRUE
// only if both hooks were successfully created+enabled.
static BOOL InitCreateProcessHooks() {
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
    Log(allOk ? "MinHook: CreateProcessA/W hooks ACTIVE"
              : "MinHook: hooks partially installed (see warnings above)");
    return allOk;
}

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

    // Wait hooks DISABLED -- they were tripping nProtect's anti-hook
    // fingerprint check. We now use thread enumeration + GetThreadContext
    // to read each thread's EIP every 5 seconds (see DumpThreadEips()
    // below). That tells us which thread is parked in
    // kernelbase!WaitForSingleObjectEx / ntdll!ZwWaitForSingleObject and
    // what the return address into Goley_'s code is -- enough to find
    // the wait site in IDA without ever installing a wait hook.
    Log("Wait hooks DISABLED -- using thread-EIP polling instead");

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
        PatchStdcallStub(termVA, 8, "kernel32!TerminateProcess");
        PatchStdcallStub(exitVA, 4, "kernel32!ExitProcess");
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
        DWORD ntTermProc = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateProcess");
        DWORD rtlExit    = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "RtlExitUserProcess");
        DWORD ntTermThr  = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateThread");
        PatchStdcallStub(ntTermProc, 8, "ntdll!NtTerminateProcess");
        PatchStdcallStub(rtlExit,    4, "ntdll!RtlExitUserProcess");
        PatchStdcallStub(ntTermThr,  8, "ntdll!NtTerminateThread");
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

        // (1c) LATE InitWaitHooks. Iki tetikleyici var:
        //   (a) val_hit + 2 sec  -- Themida'li canli yol, unpack + integrity
        //       sweep bitti, kernel32 wait stub'larina dokunmak guvenli.
        //   (b) tick > 8 sec     -- statik patch yolu (unpacked binary),
        //       val_hit hic gelmez; sabit zaman sonra yine de hook'larizi
        //       kurariz. Cogu Themida cold start'inda val_hit 60-180 sn
        //       icinde gelir, bu yuzden 8 sn'lik fallback Themida'yi
        //       bozmaz.
        if (!waitHooksInstalled &&
            ((g_valHit && (nowTick - startTick) > 2000) ||
             ((nowTick - startTick) > 8000))) {
            Log(g_valHit ? "LATE InitWaitHooks (post-val branch)"
                         : "LATE InitWaitHooks (timer branch -- statik patch yolu)");
            InitWaitHooks();
            waitHooksInstalled = TRUE;
        }

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

// DLL'in disk uzerindeki yolundan log dosyasinin yolunu hesaplar.
// Patcher su yapida bulunuyor: <repo>/src/patcher/revival_patcher.dll
// Log dosyasini repo'nun kokune koyariz: <repo>/patcher.log
static void ResolveLogPath(HMODULE hModule) {
    if (!GetModuleFileNameA(hModule, SELF_DLL_PATH, MAX_PATH)) return;
    // Once SELF_DLL_PATH'i kendi path'ine kopyaladik. Simdi log icin
    // ondan turetiyoruz: dirname -> dirname -> dirname + "\\patcher.log".
    char tmp[MAX_PATH];
    lstrcpynA(tmp, SELF_DLL_PATH, MAX_PATH);
    for (int up = 0; up < 3; up++) {
        char* slash = (char*)strrchr(tmp, '\\');
        if (!slash) break;
        *slash = 0;
    }
    if (tmp[0]) {
        wsprintfA(g_logPath, "%s\\patcher.log", tmp);
    }
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

        if (lstrcmpiA(selfBasename, "revival_wrapper.exe") == 0) {
            // === WRAPPER MODE -- EARLY RETURN, hicbir patch/hook/armor ===
            // Wrapper kendi mantigini calistirmali. patcher.dll burada hiç
            // is yapmamali. Log dosyasi = patcher_wrapper.log.
            char* slash = (char*)strrchr(g_logPath, '\\');
            if (slash) lstrcpyA(slash + 1, "patcher_wrapper.log");
            Log("DLL_PROCESS_ATTACH [WRAPPER MODE] -- EARLY RETURN, no patches");
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
                    PatchStdcallStub(termVA, 8, "[inline] kernel32!TerminateProcess");
                    PatchStdcallStub(exitVA, 4, "[inline] kernel32!ExitProcess");
                }
                if (hNt) {
                    DWORD ntTermProc = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateProcess");
                    DWORD rtlExit    = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "RtlExitUserProcess");
                    DWORD ntTermThr  = (DWORD)(ULONG_PTR)GetProcAddress(hNt, "NtTerminateThread");
                    PatchStdcallStub(ntTermProc, 8, "[inline] ntdll!NtTerminateProcess");
                    PatchStdcallStub(rtlExit,    4, "[inline] ntdll!RtlExitUserProcess");
                    PatchStdcallStub(ntTermThr,  8, "[inline] ntdll!NtTerminateThread");
                }
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
