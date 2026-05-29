#pragma once
// ============================================================================
// Constants: RVA addresses, magic values, fake parameter table.
// Separated from globals to respect SRP — these never change at runtime.
// ============================================================================
#include "typedefs.h"

// --- Themida validation bypass RVAs ---
extern const DWORD VALIDATION_RVA;     // cmp byte [esp+13h], 0
extern const DWORD SUCCESS_RVA;        // target jmp destination

// --- GameGuard result patch ---
extern const DWORD GG_RESULT_PATCH_RVA;  // mov esi, eax (after GG check call)
extern const DWORD GG_OK_STATUS;         // magic "all clear" value

// --- GameGuard CreateProcess call ---
extern const DWORD GG_CREATEPROC_CALL_RVA;

// --- MessageBoxW call site ---
extern const DWORD GG_MBW_CALL_RVA;
extern const DWORD GG_MBW_CALL_NEXT_RVA;

// --- IAT slot for diagnostics ---
extern const DWORD GOLEY_MBW_IAT_VA;

// --- Fake parameter table (Netmarble session emulation) ---
extern const FakeParam g_fakeParams[];
const char* FindFakeParam(const char* key);
