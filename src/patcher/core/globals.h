#pragma once
// ============================================================================
// Global mutable state — extern declarations only (SRP).
// Definitions live in globals.cpp.
// ============================================================================
#include "constants.h"

// --- DLL self-path (set in DllMain) ---
extern char SELF_DLL_PATH[MAX_PATH];

// --- Image base (set in PatchThread) ---
extern BYTE* g_imageBase;

// --- Process mode flags ---
extern volatile LONG g_launcherMode;
extern volatile LONG g_payloadMode;
#define IS_OBSERVER_MODE() (g_launcherMode || g_payloadMode)

// --- VEH handle ---
extern PVOID g_vehHandle;

// --- MessageBox resolved addresses ---
extern DWORD g_msgBoxAVA;
extern DWORD g_msgBoxWVA;

// --- Hit counters (thread-safe) ---
extern volatile LONG g_valHit;
extern volatile LONG g_mbaHit;
extern volatile LONG g_mbwHit;
extern volatile LONG g_ggrHit;
extern volatile LONG g_cpHit;
extern volatile LONG g_gclLogged;
extern volatile LONG g_nmrunSetParamHits;
extern volatile LONG g_nmrunGetParamHits;

// --- CreateProcess syscall VA ---
extern DWORD g_createProcessWVA;

// --- Logging ---
extern char   g_logPath[MAX_PATH];
extern HANDLE g_conHandle;

// --- Recursion guard ---
extern volatile LONG g_inHook;

// --- Thread dump tick ---
extern DWORD g_lastThreadDumpTick;

// --- Original function trampolines ---
extern ExitProcess_t      g_origExitProcess;
extern TerminateProcess_t g_origTerminateProcess;
extern CreateProcessA_t   g_origCreateProcessA;
extern CreateProcessW_t   g_origCreateProcessW;

extern WaitForSingleObject_t    g_origWFSO;
extern WaitForSingleObjectEx_t  g_origWFSOEx;
extern WaitForMultipleObjects_t g_origWFMO;
extern NtWaitForSingleObject_t  g_origNtWFSO;
extern NtQueryObject_t          g_pNtQueryObject;

extern NMRunParamSetParam_t      g_origNMRunSetParam;
extern NMRunParamSetParam2_t     g_origNMRunSetParam2;
extern NMRunParamRunProg_t       g_origNMRunRunProg;
extern NMRunParamLoad_t          g_origNMRunLoad;
extern NMRunParamGetParam_t      g_origNMRunGetParam;
extern NMRunParamExistsParam_t   g_origNMRunExistsParam;
extern NMRunParamGetParamCount_t g_origNMRunGetCount;
extern void* g_fakeHData;

extern GetCommandLineA_t g_origGetCommandLineA;
extern GetCommandLineW_t g_origGetCommandLineW;
extern char    g_fakeCmdLineA[];
extern wchar_t g_fakeCmdLineW[];

extern connect_t       g_origConnect;
extern gethostbyname_t g_origGethostbyname;
extern getaddrinfo_t   g_origGetaddrinfo;

extern CreateWindowExA_t  g_origCreateWindowExA;
extern CreateWindowExW_t  g_origCreateWindowExW;
extern RegisterClassExA_t g_origRegisterClassExA;
extern RegisterClassExW_t g_origRegisterClassExW;

extern BT_SaveSnapshot_t g_origBT_SaveSnapshot;
extern BT_SendSnapshot_t g_origBT_SendSnapshot;
extern BT_SetFlags_t     g_origBT_SetFlags;
