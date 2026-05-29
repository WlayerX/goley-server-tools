#pragma once
// ============================================================================
// Consolidated type definitions (SRP: single source of truth for all typedefs)
// ============================================================================
#include "pch.h"

// --- Process / Thread control ---
typedef VOID (WINAPI *ExitProcess_t)(UINT);
typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE, UINT);

typedef BOOL (WINAPI *CreateProcessA_t)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessW_t)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// --- Wait API hooks ---
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef DWORD (WINAPI *WaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
typedef DWORD (WINAPI *WaitForMultipleObjects_t)(DWORD, const HANDLE*, BOOL, DWORD);
typedef LONG  (NTAPI  *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG  (NTAPI  *NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// --- ntdll internal structs (no winternl.h dependency) ---
typedef struct {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING_local;

typedef struct {
    UNICODE_STRING_local Name;
} OBJECT_NAME_INFORMATION_local;

// --- Netmarble NMRunParamDLL hooks ---
typedef int (__cdecl *NMRunParamSetParam_t)(void* hData, const char* key, const char* value);
typedef int (__cdecl *NMRunParamSetParam2_t)(void* hData, int idx, const char* value);
typedef int (__cdecl *NMRunParamCreate_t)(void);
typedef int (__cdecl *NMRunParamRunProg_t)(void* hData, const char* exe, const char* args);
typedef int (__cdecl *NMRunParamLoad_t)(void* hData, int useGlobalShare, int extra);
typedef int (__cdecl *NMRunParamGetParam_t)(void* hData, const char* key, void* outBuf);
typedef int (__cdecl *NMRunParamExistsParam_t)(void* hData, const char* key);
typedef int (__cdecl *NMRunParamGetParamCount_t)(void* hData);

// --- Command line hooks ---
typedef LPSTR  (WINAPI *GetCommandLineA_t)(void);
typedef LPWSTR (WINAPI *GetCommandLineW_t)(void);

// --- Network hooks (ws2_32) ---
struct addrinfo_fwd;   // forward decl (ws2tcpip.h conflicts)
typedef int            (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef struct hostent*(WSAAPI *gethostbyname_t)(const char*);
typedef int            (WSAAPI *getaddrinfo_t)(const char*, const char*,
                                               const struct addrinfo_fwd*,
                                               struct addrinfo_fwd**);

// --- Window audit hooks ---
typedef HWND (WINAPI *CreateWindowExA_t)(DWORD, LPCSTR,  LPCSTR,  DWORD,
                                         int, int, int, int, HWND, HMENU,
                                         HINSTANCE, LPVOID);
typedef HWND (WINAPI *CreateWindowExW_t)(DWORD, LPCWSTR, LPCWSTR, DWORD,
                                         int, int, int, int, HWND, HMENU,
                                         HINSTANCE, LPVOID);
typedef ATOM (WINAPI *RegisterClassExA_t)(const WNDCLASSEXA*);
typedef ATOM (WINAPI *RegisterClassExW_t)(const WNDCLASSEXW*);

// --- BugTrap hooks ---
typedef int  (__stdcall *BT_SaveSnapshot_t)(void* excPtrs, const char* fname);
typedef int  (__stdcall *BT_SendSnapshot_t)(void* excPtrs, const char* fname);
typedef void (__stdcall *BT_SetFlags_t)(DWORD dwFlags);

// --- Shared data structs ---
struct FakeParam { const char* key; const char* value; };

typedef struct {
    HWND  foundHwnd;
    DWORD ownerPid;
} FindData;
