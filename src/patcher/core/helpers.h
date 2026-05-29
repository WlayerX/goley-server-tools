#pragma once
// ============================================================================
// Utility function prototypes (SRP: string rendering, module resolve, 
// thread diagnostics, hook guard). No typedefs here — see typedefs.h.
// ============================================================================
#include "globals.h"

// --- Hook recursion guard ---
BOOL EnterHook(void);
void LeaveHook(void);

// --- EIP classification for thread dump ---
const char* ClassifyEip(DWORD eip);

// --- Handle name resolution via NtQueryObject ---
void DescribeHandle(HANDLE h, char* buf, int bufSize);

// --- Module/address resolution ---
void ResolveAddrToModule(void* addr, char* outName, int outLen, DWORD* rvaOut);

// --- Class name rendering for logs ---
void RenderClassNameA(LPCSTR cls, char* out, int outLen);
void RenderClassNameW(LPCWSTR cls, char* out, int outLen);
void RenderInstanceModule(HINSTANCE hInst, char* out, int outLen);

// --- Window creation result logging ---
void LogCreateResult(HWND hwnd, const char* api, const char* clsTxt,
                     const char* titleTxt, int reqX, int reqY, int reqW, int reqH,
                     DWORD style, DWORD exStyle,
                     const char* callerMod, DWORD callerRva);

// --- Path basename extraction ---
void GetBasenameA(const char* path, char* outBase, int outLen);
void GetBasenameW(LPCWSTR path, char* outBase, int outLen);
void ResolveChildBasenameA(const char* lpApp, const char* lpCmd,
                           char* outBase, int outLen);
void ResolveChildBasenameW(LPCWSTR lpApp, LPCWSTR lpCmd,
                           char* outBase, int outLen);




