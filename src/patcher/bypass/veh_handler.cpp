#include "veh_handler.h"
#include "../core/logger.h"
#include "../core/helpers.h"

// ============================================================================
// EipInMainImage -- race-free "is EIP inside the main game module" predicate.
//
// The AV/ILL rescue formerly read g_imageBase, but that global is set ~700ms
// into startup by PatchThread, AFTER Themida's earliest voluntary AV/ILL probes
// fire (logs: crash @ .148/.170, g_imageBase set @ .85s). Result: inGameImage
// was false, the probes fell through to Themida -> RtlExitUserProcess -> hang.
//
// Resolve the main module's base + SizeOfImage ONCE here, independent of any
// async-set global, via GetModuleHandleA(NULL) (the module is mapped before
// DllMain, so this is valid from the very first VEH entry). SizeOfImage is read
// straight from the PE optional header at the image base (a static link-time
// field the loader maps before DllMain), guarded; falls back to 0x02000000.
// ============================================================================
static BOOL EipInMainImage(DWORD eip) {
    static volatile LONG s_init = 0;
    static DWORD s_base = 0;
    static DWORD s_size = 0;

    if (!s_base) {
        DWORD base = (DWORD)(ULONG_PTR)GetModuleHandleA(NULL);
        DWORD size = 0x02000000;  // fallback if PE parse fails
        if (base) {
            __try {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(ULONG_PTR)base;
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    PIMAGE_NT_HEADERS nt =
                        (PIMAGE_NT_HEADERS)(ULONG_PTR)(base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE &&
                        nt->OptionalHeader.SizeOfImage)
                        size = nt->OptionalHeader.SizeOfImage;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                size = 0x02000000;
            }
        }
        // Cache (idempotent under concurrent VEH entry -- identical values).
        // Publish s_size BEFORE s_base so the `!s_base` gate never pairs a fresh
        // base with a stale size==0. One-time confirmation log.
        s_size = size;
        s_base = base;
        if (base && InterlockedExchange(&s_init, 1) == 0) {
            char b[160];
            wsprintfA(b, "[veh] main image base=0x%08X size=0x%08X (rescue predicate)",
                      base, size);
            Log(b);
        }
    }

    return s_base && eip >= s_base && eip < s_base + s_size;
}

// ============================================================================
// DumpCrashContext -- full register + stack-walk dump to patcher_crash.log.
//
// Pure logging, NEVER mutates the context. Called log-before-rescue from the
// fatal-exception path in VehHandler so we capture exactly WHERE a silent
// termination originates before the existing AV-rescue swallows or advances.
//
// Why a separate crash file: patcher.log floods with HWBP/wait traffic; the
// crash dump must survive a silent exit, so we isolate it (LogCrash closes the
// file handle per call = effectively flushed even if the process dies next).
// ============================================================================
static void DumpCrashContext(PEXCEPTION_POINTERS exc, const char* tag) {
    PCONTEXT c = exc->ContextRecord;
    PEXCEPTION_RECORD r = exc->ExceptionRecord;
    char buf[512];

    DWORD faultAddr = r->NumberParameters > 1 ? (DWORD)r->ExceptionInformation[1] : 0;
    DWORD access    = r->NumberParameters > 0 ? (DWORD)r->ExceptionInformation[0] : 0;
    const char* accessTxt = (access == 0) ? "read" : (access == 1) ? "write"
                          : (access == 8) ? "DEP-execute" : "?";

    char eipMod[64] = {0}; DWORD eipRva = 0;
    ResolveAddrToModule((void*)c->Eip, eipMod, sizeof(eipMod), &eipRva);

    wsprintfA(buf, "================ CRASH [%s] code=0x%08X tid=%lu ================",
              tag, r->ExceptionCode, GetCurrentThreadId());
    LogCrash(buf);
    wsprintfA(buf, "  EIP=0x%08X (%s+0x%X / %s)  fault=0x%08X (%s)  flags=0x%X",
              c->Eip, eipMod, eipRva, ClassifyEip(c->Eip), faultAddr, accessTxt,
              r->ExceptionFlags);
    LogCrash(buf);

    // 16 bytes at the faulting EIP -- characterizes the opcode stream we keep
    // hitting (e.g. the Themida VM site). Guarded: the EIP page may be unmapped.
    {
        char hex[80]; int off = 0;
        __try {
            const BYTE* p = (const BYTE*)(ULONG_PTR)c->Eip;
            for (int i = 0; i < 16; i++)
                off += wsprintfA(hex + off, "%02X ", p[i]);
            wsprintfA(buf, "  bytes@EIP=%s", hex);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            wsprintfA(buf, "  bytes@EIP=<unreadable>");
        }
        LogCrash(buf);
    }
    wsprintfA(buf, "  EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X",
              c->Eax, c->Ebx, c->Ecx, c->Edx);
    LogCrash(buf);
    wsprintfA(buf, "  ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X EFL=0x%08X",
              c->Esi, c->Edi, c->Ebp, c->Esp, c->EFlags);
    LogCrash(buf);
    wsprintfA(buf, "  DR0=0x%08X DR1=0x%08X DR2=0x%08X DR3=0x%08X DR6=0x%08X DR7=0x%08X",
              c->Dr0, c->Dr1, c->Dr2, c->Dr3, c->Dr6, c->Dr7);
    LogCrash(buf);

    // Stack walk: read 24 dwords from ESP; symbolicate code-like values so the
    // caller chain is visible even without a debugger. Guarded read (the stack
    // itself may be partially unmapped during a Themida teardown).
    LogCrash("  --- stack walk (ESP+0x00 .. +0x5C) ---");
    for (int i = 0; i < 24; i++) {
        DWORD val = 0;
        __try {
            val = *(volatile DWORD*)(ULONG_PTR)(c->Esp + i * 4);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            wsprintfA(buf, "  stk[+0x%02X] <unreadable>", i * 4);
            LogCrash(buf);
            break;
        }
        // Only symbolicate values that look like code addresses (inside a module).
        char m[64] = {0}; DWORD rva = 0;
        ResolveAddrToModule((void*)val, m, sizeof(m), &rva);
        if (lstrcmpA(m, "<anon>") != 0) {
            wsprintfA(buf, "  stk[+0x%02X]=0x%08X  %s+0x%X (%s)",
                      i * 4, val, m, rva, ClassifyEip(val));
            LogCrash(buf);
        }
    }
    LogCrash("================ END CRASH ================");
}


// ============================================================================
// Last-chance UnhandledExceptionFilter -- the killer 0xC0000005 never reaches
// our first-chance VEH (only the 2 rescued dumps ever appear, cap is 12). An
// unhandled exception that walks past every SEH frame lands HERE right before
// process death, so this is where we finally capture it. Chains to whatever
// top-level filter was installed before us (Themida's, typically) so behavior
// is preserved -- this is pure instrumentation.
// ============================================================================
static LPTOP_LEVEL_EXCEPTION_FILTER g_prevUef = NULL;

LONG WINAPI LastChanceFilter(PEXCEPTION_POINTERS exc) {
    DumpCrashContext(exc, "UNHANDLED-LASTCHANCE");
    if (g_prevUef) return g_prevUef(exc);   // preserve Themida's UEF behavior
    return EXCEPTION_EXECUTE_HANDLER;        // else let it die (logged)
}

void InstallLastChanceFilter(void) {
    g_prevUef = SetUnhandledExceptionFilter(LastChanceFilter);
    char mod[64] = {0}; DWORD rva = 0;
    if (g_prevUef) ResolveAddrToModule((void*)g_prevUef, mod, sizeof(mod), &rva);
    char buf[160];
    wsprintfA(buf, "InstallLastChanceFilter: prev=0x%p (%s+0x%X)",
              g_prevUef, g_prevUef ? mod : "<none>", rva);
    Log(buf);
}

BOOL ReassertLastChanceFilter(void) {
    // Re-install ours; the return value is whoever was the top-level filter just
    // now. If it isn't ours, someone (Themida?) replaced it since last time.
    LPTOP_LEVEL_EXCEPTION_FILTER nowPrev = SetUnhandledExceptionFilter(LastChanceFilter);
    if (nowPrev != LastChanceFilter) {
        // Keep chaining to the most-recent foreign filter so we don't drop it.
        if (nowPrev) g_prevUef = nowPrev;
        return TRUE;
    }
    return FALSE;
}


// Livelock guard caps for RescueAdvanceEip (tunable). Global = total swallows
// before we permanently hand back to Themida's VEH; Repeat = consecutive
// swallows at the SAME EIP before we hand that one address back (Themida
// looping a region). Sized generously for heavy voluntary-AV Themida configs.
#define GOLEY_RESCUE_TOTAL_CAP   100000
#define GOLEY_RESCUE_REPEAT_CAP  256

// ============================================================================
// RescueAdvanceEip -- the Katman-5 "voluntary AV / illegal-instruction" swallow.
//
// Themida deliberately throws 0xC0000005 / 0xC000001D INSIDE the game module
// (Goley_.exe) as anti-debug "is a debugger swallowing this?" probes. We must
// ADVANCE EIP past the faulting/illegal instruction (naive continue without
// advancing re-fires the same address -> 50k exceptions/3s livelock). Uses
// HDE32 for length; on UD2/F_ERROR it still advances (sane HDE len, else a
// 2-byte fallback) so EIP is never left parked on the bad instruction.
//
// Returns TRUE if it mutated the CONTEXT for forward progress (caller returns
// EXCEPTION_CONTINUE_EXECUTION). Returns FALSE -> caller falls through to
// EXCEPTION_CONTINUE_SEARCH (= safe pre-fix behavior; a livelock can never
// re-form because the guards below cap it). Only mutates EIP/ESP -- no .text
// write, so Themida integrity checks stay happy.
// ============================================================================
static BOOL RescueAdvanceEip(PEXCEPTION_POINTERS exc, DWORD eip, const char* tag) {
    // (A) Global hard cap -- a runaway permanently surrenders to Themida's VEH.
    static volatile LONG g_rescueTotal = 0;
    LONG total = InterlockedIncrement(&g_rescueTotal);
    if (total > GOLEY_RESCUE_TOTAL_CAP) {
        static volatile LONG warned = 0;
        if (InterlockedIncrement(&warned) == 1)
            Log("[rescue] total swallow cap reached -> handing back to Themida VEH");
        return FALSE;
    }

    // (B) Same-EIP repeat guard. Normal advance always changes EIP, so a healthy
    // stream never trips this; only a Themida region-loop on one address does.
    static volatile LONG g_lastEip     = 0;
    static volatile LONG g_repeatCount = 0;
    LONG prev = InterlockedExchange(&g_lastEip, (LONG)eip);
    LONG rep;
    if ((DWORD)prev == eip) rep = InterlockedIncrement(&g_repeatCount);
    else { InterlockedExchange(&g_repeatCount, 0); rep = 0; }
    if (rep > GOLEY_RESCUE_REPEAT_CAP) {
        static volatile LONG rWarned = 0;
        if (InterlockedIncrement(&rWarned) <= 5) {
            char b[160];
            wsprintfA(b, "[rescue-%s] same EIP=0x%X swallowed %ld x -> CONTINUE_SEARCH", tag, eip, rep);
            Log(b);
        }
        return FALSE;
    }

    // (C) Invalid EIP (0 / -1 / near-null): simulate a RET to recover.
    if (eip < 0x1000 || eip > 0xFFFFFFF0) {
        DWORD* esp = (DWORD*)exc->ContextRecord->Esp;
        __try {
            DWORD retAddr = esp[0];
            exc->ContextRecord->Eip  = retAddr;
            exc->ContextRecord->Esp += 4;
            static volatile LONG c = 0;
            if (InterlockedIncrement(&c) <= 50) {
                char b[160];
                wsprintfA(b, "[rescue-%s] invalid EIP 0x%X -> simulated RET to 0x%X", tag, eip, retAddr);
                Log(b);
            }
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            static volatile LONG f = 0;
            if (InterlockedIncrement(&f) <= 20)
                Log("[rescue] invalid EIP + unreadable stack -> CONTINUE_SEARCH");
            return FALSE;
        }
    }

    // (D) Valid EIP -- HDE32 length advance with F_ERROR/UD2 fallback.
    unsigned int instLen = 0, flags = 0;
    __try {
        hde32s hs;
        instLen = hde32_disasm((const void*)eip, &hs);
        flags   = hs.flags;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static volatile LONG e = 0;
        if (InterlockedIncrement(&e) <= 20) {
            char b[160];
            wsprintfA(b, "[rescue-%s] disasm faulted @0x%X -> CONTINUE_SEARCH", tag, eip);
            Log(b);
        }
        return FALSE;
    }

    // Pick an advance that ALWAYS makes progress:
    //   clean decode (1..15, no F_ERROR)      -> instLen
    //   F_ERROR but HDE reports sane len 1..15 -> trust it
    //   else (len 0 / >15, e.g. UD2 = 0F 0B)   -> 2-byte fallback
    BOOL clean = (instLen >= 1 && instLen <= 15 && !(flags & F_ERROR));
    unsigned int adv = (instLen >= 1 && instLen <= 15) ? instLen : 2;

    exc->ContextRecord->Eip = eip + adv;

    static volatile LONG sw = 0;
    LONG n = InterlockedIncrement(&sw);
    if (n <= 100) {
        char b[256];
        wsprintfA(b, "[rescue-%s] EIP 0x%X -> 0x%X adv=%u (%s len=%u flags=0x%X) rep=%ld tot=%ld",
                  tag, eip, eip + adv, adv, clean ? "clean" : "FORCED",
                  instLen, flags, rep, total);
        Log(b);
        if (n == 100) Log("[rescue] swallow-log cap reached (further swallows silent)");
    }
    return TRUE;
}


LONG CALLBACK VehHandler(PEXCEPTION_POINTERS exc) {
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
        // -- HWBP WaitForMultipleObjects fallback (Commit B, behind g_useHwbpWait)
        //    DR3 is armed on kernel32!WaitForMultipleObjects entry only AFTER
        //    g_cpHit retires the NtCreateUserProcess BP (temporal slot reuse).
        //    At the export entry (stdcall, ret 0x10): [esp]=ret, [esp+4]=nCount,
        //    [esp+8]=lpHandles, [esp+0xC]=bWaitAll, [esp+0x10]=dwTimeout.
        //    Mirrors HookedWaitForMultipleObjects (hook_wait.cpp) GameMon
        //    2-handle auto-signal, but via debug registers (no .text write).
        if (g_useHwbpWait && g_wfmoVA && eip == g_wfmoVA) {
            DWORD* esp     = (DWORD*)exc->ContextRecord->Esp;
            DWORD  retAddr = esp[0];
            DWORD  nCount  = esp[1];
            HANDLE* pHandles = (HANDLE*)esp[2];
            DWORD  bWaitAll  = esp[3];

            int eventIndex = -1;
            if (g_hGameMonProcess && pHandles && !bWaitAll && nCount == 2) {
                __try {
                    int gmIdx = -1;
                    for (DWORD i = 0; i < nCount; i++)
                        if (pHandles[i] == g_hGameMonProcess) { gmIdx = (int)i; break; }
                    if (gmIdx != -1) {
                        eventIndex = (gmIdx == 0) ? 1 : 0;
                        SetEvent(pHandles[eventIndex]);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    eventIndex = -1;
                }
            }

            if (eventIndex != -1) {
                // Fake the stdcall return WITHOUT running the function: pop the
                // return address + 4 dword args (ret 0x10). EAX = result.
                DWORD espBefore = exc->ContextRecord->Esp;
                exc->ContextRecord->Eax  = WAIT_OBJECT_0 + eventIndex;
                exc->ContextRecord->Eip  = retAddr;
                exc->ContextRecord->Esp += 4 + 0x10;   // ret + 4 stdcall args
                char buf[256];
                wsprintfA(buf, "[HWBP-WFMO] tid=%lu n=%lu GameMon -> faked WAIT_OBJECT_0+%d ret=0x%X esp 0x%X->0x%X",
                          GetCurrentThreadId(), nCount, eventIndex, retAddr,
                          espBefore, exc->ContextRecord->Esp);
                Log(buf);
                InterlockedIncrement(&g_hwbpWaitHit);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // Non-GameMon wait: do NOT fake. Disarm DR3 for this thread and let
            // the real WaitForMultipleObjects run natively (observer-safe). The
            // refresh loop re-arms DR3 on the next sweep.
            exc->ContextRecord->Dr3  = 0;
            exc->ContextRecord->Dr7 &= ~0x40;   // clear L3
            return EXCEPTION_CONTINUE_EXECUTION;
        }

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
            // De-silenced: if the KILLER AV is this one in disguise, we must see
            // it. Capped so a real benign probe flood can't spam the log.
            static volatile LONG g_iatProbeLog = 0;
            if (InterlockedIncrement(&g_iatProbeLog) <= 10) {
                char b[160];
                wsprintfA(b, "[veh] IAT-probe AV swallowed silently @EIP=0x%X fault=0x%X",
                          eip, faultAddr);
                Log(b);
            }
            return EXCEPTION_CONTINUE_SEARCH;
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
        // ---- AGGRESSIVE CRASH DUMP (log-before-rescue) ----------------------
        // Capture full context for genuinely fatal codes the moment they fire,
        // BEFORE the AV-rescue below swallows/advances them. This is what tells
        // us WHERE the silent termination originates. Capped so a Themida AV
        // flood can't starve its own VEH chain via log volume.
        //   0xC0000005 = ACCESS_VIOLATION
        //   0xC00000FD = STACK_OVERFLOW
        //   0xC0000409 = FAST_FAIL (__fastfail / stack cookie / GS)
        //   0xC000001D = ILLEGAL_INSTRUCTION (first occurrence only)
        {
            static volatile LONG g_crashDumps = 0;
            BOOL fatal = (code == EXCEPTION_ACCESS_VIOLATION ||
                          code == EXCEPTION_STACK_OVERFLOW   ||
                          code == 0xC0000409 /* FAST_FAIL */  ||
                          code == 0xC000001D /* ILLEGAL_INSTRUCTION */);
            if (fatal) {
                LONG d = InterlockedIncrement(&g_crashDumps);
                if (d <= 12) {
                    const char* nm = (code == EXCEPTION_ACCESS_VIOLATION) ? "ACCESS_VIOLATION"
                                   : (code == EXCEPTION_STACK_OVERFLOW)   ? "STACK_OVERFLOW"
                                   : (code == 0xC0000409)                 ? "FAST_FAIL"
                                   : "ILLEGAL_INSTRUCTION";
                    DumpCrashContext(exc, nm);
                    if (d == 12) LogCrash("(crash-dump cap reached -- further fatal exceptions silent)");
                }
            }
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

        // -- ACCESS_VIOLATION rescue. Now ALSO covers the game's own module
        //    (Katman 5): Themida's voluntary AVs at eip < 0x70000000 were
        //    previously left to its handler -> "초기화중" deadlock. We swallow
        //    them by advancing EIP. faultAddr-benign cases already filtered above.
        if (code == EXCEPTION_ACCESS_VIOLATION) {
            BOOL inGameImage = EipInMainImage(eip);
            BOOL shouldRescue = (eip >= 0x70000000 || eip == 0 || eip == 0xFFFFFFFF || inGameImage);
            if (shouldRescue && RescueAdvanceEip(exc, eip, "AV"))
                return EXCEPTION_CONTINUE_EXECUTION;
        }

        // -- ILLEGAL_INSTRUCTION (0xC000001D) rescue. This path did NOT exist
        //    before -- 0xC000001D only logged then fell through to Themida.
        //    UD2 (0F 0B) makes HDE32 set F_ERROR; RescueAdvanceEip handles that
        //    via its fallback so EIP advances past the illegal opcode instead of
        //    re-faulting forever. (illegal-instr EIP is never 0, so no null case.)
        if (code == EXCEPTION_ILLEGAL_INSTRUCTION /* 0xC000001D */) {
            BOOL inGameImage = EipInMainImage(eip);
            BOOL shouldRescue = (eip >= 0x70000000 || inGameImage);
            if (shouldRescue && RescueAdvanceEip(exc, eip, "ILL"))
                return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


