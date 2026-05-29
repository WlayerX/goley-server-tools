#pragma once
#include "../core/globals.h"

// ntdll-level process-exit interception. Goley_'s silent termination does NOT
// flow through kernel32!ExitProcess/TerminateProcess (those are already hooked
// and spin), so it most likely funnels through the ntdll syscall stubs below.
// These hooks log the FULL caller stack (to patcher_crash.log) before deciding
// to neutralize the exit -- replacing the old silent EB-FE hang-stub which gave
// us no call-site information and tampered ntdll .text.
LONG NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, LONG ExitStatus);
VOID NTAPI HookedRtlExitUserProcess(UINT uExitCode);

// Returns the number of exit APIs successfully intercepted via MinHook. Any
// stub that fails to trampoline falls back to the legacy PatchHangStub so the
// "don't die" guarantee is never lost.
int InitExitHooks(void);
