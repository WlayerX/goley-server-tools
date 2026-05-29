#pragma once
// ============================================================================
// Logging system (SRP: console + file logging)
// ============================================================================
#include "globals.h"

void InitDebugConsole();
void Log(const char* msg);
// LogCrash: write to a dedicated patcher_crash.log sibling of g_logPath so a
// silent termination's full context survives even if patcher.log is noisy.
// Path is derived lazily from g_logPath on first call (tracks per-mode rename
// done in DllMain). Mirrors to console like Log().
void LogCrash(const char* msg);
void LogLoadedModulesSnapshot(const char* tag);
void ResolveLogPath(HMODULE hModule);
