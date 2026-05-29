#pragma once
#include "../core/globals.h"

int SetHardwareBreakpointAllThreads(DWORD t0, DWORD t1, DWORD t2, DWORD t3 = 0);
int ClearHardwareBreakpointAllThreads();
void DumpThreadEips(void);
