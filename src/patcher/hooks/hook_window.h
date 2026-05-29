#pragma once
#include "../core/globals.h"

ATOM WINAPI HookedRegisterClassExA(const WNDCLASSEXA* lpwcx);
ATOM WINAPI HookedRegisterClassExW(const WNDCLASSEXW* lpwcx);
HWND WINAPI HookedCreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
BOOL InitWindowAuditHooks();
