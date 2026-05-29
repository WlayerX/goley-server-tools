#pragma once
#include "../core/globals.h"

// Direct-syscall ground truth for NtQueryInformationProcess (Commit C).
//
// Purpose: read the REAL ExitStatus the kernel reports, bypassing both the
// user-mode ntdll stub patch and our own MinHook NtQueryInformationProcess
// detour, so we can compare hooked-vs-real and detect whether something queries
// our exit state via a path that skips our hook (a silent-exit hypothesis).
//
// WOW64-safe mechanism (no .text write, no hardcoded sysenter): we build a tiny
// executable gadget  [ mov eax, ssn ; jmp <ntdll stub + 5> ]  that supplies our
// own syscall number then jumps PAST the stub's own `mov eax,imm32` into its
// real (version-specific) WOW64 transition tail. Because MinHook only overwrites
// the first 5 bytes (the mov eax,imm32), the transition tail stays intact even
// after the stub is hooked -- so the gadget reaches the kernel unhooked.

// Resolve syscall number by parsing the clean ntdll stub prologue (B8 imm32).
// Returns 0xFFFFFFFF if the stub is not the canonical `mov eax, imm32` form.
DWORD ResolveSyscallNumber(const char* ntFuncName);

// Build the direct gadget for NtQueryInformationProcess. MUST be called BEFORE
// any hook patches the stub. Returns TRUE on success. Logs SSN + mechanism.
BOOL  InitDirectSyscalls(void);

// Real, unhooked NtQueryInformationProcess via the gadget. NULL-safe: if the
// gadget wasn't built, falls back to the live (possibly hooked) stub.
LONG  DirectNtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);

// Diagnostic: query ProcessBasicInformation via the live (hooked) stub AND via
// the direct gadget, log both ExitStatus values side-by-side. A divergence
// means our hook is actively rewriting the value some caller sees.
void  CompareNtQipHookedVsReal(HANDLE hProc, const char* tag);
