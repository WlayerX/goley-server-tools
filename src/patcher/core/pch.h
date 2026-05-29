#pragma once
// ============================================================================
// Precompiled Header -- tum patcher modulleri bunu include eder.
// winsock2.h MUTLAKA windows.h'tan ONCE gelmeli (WinSock redefinition hatasi).
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

// MinHook: trampoline-based API hook framework.
#include "MinHook.h"

// HDE32: Hacker Disassembler Engine (x86 instruction length decoder).
extern "C" {
#include "hde/hde32.h"
}
