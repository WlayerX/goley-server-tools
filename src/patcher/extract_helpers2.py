import re

with open('patcher.cpp', 'r', encoding='utf-8') as f:
    code = f.read()
    lines = code.split('\n')

funcs = [
    'static inline BOOL EnterHook', 'static inline void LeaveHook',
    'static const char* ClassifyEip', 'static void DescribeHandle',
    'static const char* FindFakeParam', 'static void ResolveAddrToModule',
    'static void RenderClassNameA', 'static void RenderClassNameW',
    'static void RenderInstanceModule', 'static void LogCreateResult',
    'static BOOL PatchStdcallStub', 'static BOOL PatchMessageBoxStub',
    'static int WINAPI FakeMessageBoxW', 'static int ScanAndReplaceFnPointer',
    'static BOOL PatchIATSlot', 'static int HookKillApis',
    'static int SetHardwareBreakpointAllThreads', 'static int ClearHardwareBreakpointAllThreads',
    'static BOOL CALLBACK FindGGDialogProc'
]

def extract_braces(code, start_line_idx):
    lines = code.split('\n')
    extracted = []
    brace_count = 0
    found_first = False
    for i in range(start_line_idx, len(lines)):
        line = lines[i]
        extracted.append(line)
        for char in line:
            if char == '{':
                brace_count += 1
                found_first = True
            elif char == '}':
                brace_count -= 1
        if found_first and brace_count == 0:
            break
    return '\n'.join(extracted)

impls = []
decls = []

for f_sig in funcs:
    for i, line in enumerate(lines):
        if line.startswith(f_sig):
            impl = extract_braces(code, i)
            # Remove static/inline
            impl = re.sub(r'^static\s+(inline\s+)?', '', impl)
            impls.append(impl)
            
            decl = impl.split('{')[0].strip() + ';'
            decls.append(decl)
            break

with open('core/helpers.cpp', 'w', encoding='utf-8') as f:
    f.write('#include "helpers.h"\n#include "globals.h"\n#include "logger.h"\n#include <tlhelp32.h>\n#include <psapi.h>\n\n')
    f.write('\n\n'.join(impls))

with open('core/helpers.h', 'w', encoding='utf-8') as f:
    f.write('#pragma once\n#include <windows.h>\n#include <winternl.h>\n\n')
    f.write(open('core/helpers_typedefs.h', 'r', encoding='utf-8').read())
    f.write('\n\n')
    f.write('\n'.join(decls))

print("Created helpers.cpp and helpers.h")
