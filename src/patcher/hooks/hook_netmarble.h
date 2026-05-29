#pragma once
#include "../core/globals.h"

int __cdecl HookedNMRunSetParam(void* hData, const char* key, const char* value);
int __cdecl HookedNMRunSetParam2(void* hData, int idx, const char* value);
int __cdecl HookedNMRunLoad(void* hData, int flag, int extra);
int __cdecl HookedNMRunGetParam(void* hData, const char* key, void* outBuf);
int __cdecl HookedNMRunExistsParam(void* hData, const char* key);
int __cdecl HookedNMRunGetParamCount(void* hData);
int __cdecl HookedNMRunRunProg(void* hData, const char* exe, const char* args);
BOOL InitNMRunParamLauncherHooks();
BOOL InitNMRunParamGameHooks();
