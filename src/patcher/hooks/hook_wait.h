#pragma once
#include "../core/globals.h"

DWORD WINAPI HookedWaitForSingleObject(HANDLE hObj, DWORD dwTimeout);
DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE hObj, DWORD dwTimeout, BOOL bAlertable);
DWORD WINAPI HookedWaitForMultipleObjects(DWORD nCount, const HANDLE* pHandles, BOOL bWaitAll, DWORD dwTimeout);
void InitWaitHooks();
