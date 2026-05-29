#pragma once
#include "../core/globals.h"

// IPC / shared-memory / driver observer hooks. PURE PASS-THROUGH logging -- no
// behavior change. Goal: detect whether Goley_ establishes a GameGuard
// heartbeat the sleeping dummy_gg.exe fails to service:
//   * CreateFileMapping / OpenFileMapping / MapViewOfFile  -> shared memory IPC
//   * DeviceIoControl                                       -> GameGuard driver
// Each call logs name/size/IOCTL + caller module+RVA so the handshake (if any)
// is visible in patcher.log before we decide how to spoof it.

typedef HANDLE (WINAPI *CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE (WINAPI *CreateFileMappingW_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef HANDLE (WINAPI *OpenFileMappingA_t)(DWORD, BOOL, LPCSTR);
typedef HANDLE (WINAPI *OpenFileMappingW_t)(DWORD, BOOL, LPCWSTR);
typedef LPVOID (WINAPI *MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LPVOID (WINAPI *MapViewOfFileEx_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
typedef BOOL   (WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

HANDLE WINAPI HookedCreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
HANDLE WINAPI HookedCreateFileMappingW(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
HANDLE WINAPI HookedOpenFileMappingA(DWORD, BOOL, LPCSTR);
HANDLE WINAPI HookedOpenFileMappingW(DWORD, BOOL, LPCWSTR);
LPVOID WINAPI HookedMapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
LPVOID WINAPI HookedMapViewOfFileEx(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
BOOL   WINAPI HookedDeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

BOOL InitIpcHooks(void);
