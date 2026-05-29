#include "hwbp.h"
#include "../core/logger.h"
#include "../core/helpers.h"

int SetHardwareBreakpointAllThreads(DWORD t0, DWORD t1, DWORD t2, DWORD t3) {
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


int ClearHardwareBreakpointAllThreads() {
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


void DumpThreadEips(void) {
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


