#pragma once
// ============================================================================
// Logging system (SRP: console + file logging)
// ============================================================================
#include "globals.h"

void InitDebugConsole();
void Log(const char* msg);
void LogLoadedModulesSnapshot(const char* tag);
void ResolveLogPath(HMODULE hModule);
