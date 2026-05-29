#include "globals.h"

// --- DLL self-path ---
char SELF_DLL_PATH[MAX_PATH] = {0};

// --- Image base ---
BYTE* g_imageBase = NULL;

// --- Process mode flags ---
volatile LONG g_launcherMode = 0;
volatile LONG g_payloadMode  = 0;

// --- VEH handle ---
PVOID g_vehHandle = NULL;

// --- MessageBox resolved addresses ---
DWORD g_msgBoxAVA = 0;
DWORD g_msgBoxWVA = 0;

// --- Hit counters ---
volatile LONG g_valHit = 0;
volatile LONG g_mbaHit = 0;
volatile LONG g_mbwHit = 0;
volatile LONG g_ggrHit = 0;
volatile LONG g_cpHit  = 0;
volatile LONG g_gclLogged = 0;
volatile LONG g_nmrunSetParamHits = 0;
volatile LONG g_nmrunGetParamHits = 0;

// --- CreateProcess syscall VA ---
DWORD g_createProcessWVA = 0;

// --- Logging ---
char   g_logPath[MAX_PATH] = {0};
HANDLE g_conHandle = INVALID_HANDLE_VALUE;

// --- Recursion guard ---
volatile LONG g_inHook = 0;

// --- Thread dump ---
DWORD g_lastThreadDumpTick = 0;

// --- Original function trampolines ---
ExitProcess_t      g_origExitProcess      = NULL;
TerminateProcess_t g_origTerminateProcess = NULL;
CreateProcessA_t   g_origCreateProcessA   = NULL;
CreateProcessW_t   g_origCreateProcessW   = NULL;

WaitForSingleObject_t    g_origWFSO   = NULL;
WaitForSingleObjectEx_t  g_origWFSOEx = NULL;
WaitForMultipleObjects_t g_origWFMO   = NULL;
NtWaitForSingleObject_t  g_origNtWFSO = NULL;
NtQueryObject_t          g_pNtQueryObject = NULL;

NMRunParamSetParam_t      g_origNMRunSetParam    = NULL;
NMRunParamSetParam2_t     g_origNMRunSetParam2   = NULL;
NMRunParamRunProg_t       g_origNMRunRunProg     = NULL;
NMRunParamLoad_t          g_origNMRunLoad        = NULL;
NMRunParamGetParam_t      g_origNMRunGetParam    = NULL;
NMRunParamExistsParam_t   g_origNMRunExistsParam = NULL;
NMRunParamGetParamCount_t g_origNMRunGetCount    = NULL;
void* g_fakeHData = NULL;

GetCommandLineA_t g_origGetCommandLineA = NULL;
GetCommandLineW_t g_origGetCommandLineW = NULL;
char    g_fakeCmdLineA[] = "Goley_.exe";
wchar_t g_fakeCmdLineW[] = L"Goley_.exe";

connect_t       g_origConnect       = NULL;
gethostbyname_t g_origGethostbyname = NULL;
getaddrinfo_t   g_origGetaddrinfo   = NULL;

CreateWindowExA_t  g_origCreateWindowExA  = NULL;
CreateWindowExW_t  g_origCreateWindowExW  = NULL;
RegisterClassExA_t g_origRegisterClassExA = NULL;
RegisterClassExW_t g_origRegisterClassExW = NULL;

BT_SaveSnapshot_t g_origBT_SaveSnapshot = NULL;
BT_SendSnapshot_t g_origBT_SendSnapshot = NULL;
BT_SetFlags_t     g_origBT_SetFlags     = NULL;
