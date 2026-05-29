#pragma once
#include "../core/globals.h"

DWORD WINAPI PatchThread(LPVOID lpParam);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved);
