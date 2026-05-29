#pragma once
// ============================================================================
// Memory patching utilities (SRP: all raw memory writes isolated here)
// ============================================================================
#include "globals.h"

// Inline-patch a __stdcall(N args) function to: mov eax, 1; ret <retBytes>
BOOL PatchStdcallStub(DWORD funcVA, int retBytes, const char* name);
BOOL PatchMessageBoxStub(DWORD funcVA, const char* name);

// Fake MessageBoxW that returns IDOK without showing any dialog
int WINAPI FakeMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

// Scan process memory for function pointer DWORDs and optionally replace them
int ScanAndReplaceFnPointer(DWORD target, DWORD replacement, const char* name, BOOL dryRun);

// Overwrite a DWORD at the given VA (for IAT slot rewriting)
BOOL PatchIATSlot(DWORD slotVA, DWORD newValue, const char* name);


