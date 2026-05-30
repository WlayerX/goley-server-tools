#pragma once
#include "../core/globals.h"

LONG CALLBACK VehHandler(PEXCEPTION_POINTERS exc);

// Last-chance UnhandledExceptionFilter: captures the fatal exception that
// escapes the first-chance VEH, right before process death (diagnostics).
LONG WINAPI LastChanceFilter(PEXCEPTION_POINTERS exc);
void InstallLastChanceFilter(void);      // call once, after VEH install
BOOL ReassertLastChanceFilter(void);     // call periodically; TRUE if it was replaced
