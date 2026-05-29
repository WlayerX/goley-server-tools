#include "veh_handler.h"
#include "../core/logger.h"
#include "../core/helpers.h"

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
                    return EXCEPTION_CONTINUE_EXECUTION;
                } else {
                    return EXCEPTION_CONTINUE_SEARCH;
                }
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


