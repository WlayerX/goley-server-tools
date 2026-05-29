#pragma once
#include "../core/globals.h"

int __stdcall HookedBT_SaveSnapshot(void* excPtrs, const char* fname);
int __stdcall HookedBT_SendSnapshot(void* excPtrs, const char* fname);
void __stdcall HookedBT_SetFlags(DWORD dwFlags);
BOOL InitBugTrapHooks();
