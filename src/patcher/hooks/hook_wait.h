#pragma once
#include "../core/globals.h"

DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout);
DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout, BOOL bAlertable);
DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount, const HANDLE* pHandles, BOOL bWaitAll, DWORD dwTimeout);
DWORD WINAPI HookedWaitForMultipleObjectsEx(DWORD nCount, const HANDLE* pHandles, BOOL bWaitAll, DWORD dwTimeout, BOOL bAlertable);
DWORD WINAPI HookedMsgWaitForMultipleObjects(DWORD nCount, const HANDLE* pHandles, BOOL fWaitAll, DWORD dwTimeout, DWORD dwWakeMask);
DWORD WINAPI HookedMsgWaitForMultipleObjectsEx(DWORD nCount, const HANDLE* pHandles, DWORD dwTimeout, DWORD dwWakeMask, DWORD dwFlags);
LONG NTAPI HookedNtWaitForSingleObject(HANDLE hObj, BOOLEAN bAlertable, PLARGE_INTEGER pTimeout);
void InitWaitHooks();
