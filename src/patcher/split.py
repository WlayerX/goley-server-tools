import re
import os

with open('patcher.cpp', 'r', encoding='utf-8') as f:
    lines = f.readlines()

def get_block(start_line_idx):
    idx = start_line_idx
    while idx < len(lines) and '{' not in lines[idx]:
        idx += 1
    if idx == len(lines):
        return None, None
    
    # We found the first brace
    open_braces = 0
    in_str = False
    in_char = False
    in_comment = False
    escape = False
    
    start_brace_found = False
    end_idx = idx
    for i in range(idx, len(lines)):
        line = lines[i]
        j = 0
        while j < len(line):
            c = line[j]
            if not in_str and not in_char and not in_comment:
                if c == '/' and j + 1 < len(line) and line[j+1] == '/':
                    break # end of line comment
                elif c == '/' and j + 1 < len(line) and line[j+1] == '*':
                    in_comment = True
                    j += 1
                elif c == '"':
                    in_str = True
                elif c == "'":
                    in_char = True
                elif c == '{':
                    open_braces += 1
                    start_brace_found = True
                elif c == '}':
                    open_braces -= 1
                    if start_brace_found and open_braces == 0:
                        return start_line_idx, i
            elif in_comment:
                if c == '*' and j + 1 < len(line) and line[j+1] == '/':
                    in_comment = False
                    j += 1
            elif in_str:
                if c == '\\':
                    j += 1
                elif c == '"':
                    in_str = False
            elif in_char:
                if c == '\\':
                    j += 1
                elif c == "'":
                    in_char = False
            j += 1
    return start_line_idx, end_idx

# Map function names to their new module
module_map = {
    'InitDebugConsole': 'core/logger',
    'Log': 'core/logger',
    'LogCreateResult': 'core/logger',
    'ResolveLogPath': 'core/logger',
    'LogLoadedModulesSnapshot': 'core/logger',
    
    'GetBasenameA': 'core/utils',
    'GetBasenameW': 'core/utils',
    'ResolveChildBasenameA': 'core/utils',
    'ResolveChildBasenameW': 'core/utils',
    'ResolveAddrToModule': 'core/utils',
    'RenderClassNameA': 'core/utils',
    'RenderClassNameW': 'core/utils',
    'RenderInstanceModule': 'core/utils',
    'DescribeHandle': 'core/utils',
    
    'PatchStdcallStub': 'hooks/hook_utils',
    'PatchMessageBoxStub': 'hooks/hook_utils',
    'PatchIATSlot': 'hooks/hook_utils',
    'ScanAndReplaceFnPointer': 'hooks/hook_utils',
    'EnterHook': 'hooks/hook_utils',
    'LeaveHook': 'hooks/hook_utils',

    'HookedCreateProcessA': 'hooks/hook_process',
    'HookedCreateProcessW': 'hooks/hook_process',
    'InitCreateProcessHooks': 'hooks/hook_process',
    'ApcInjectChild': 'hooks/hook_process',
    'HookKillApis': 'hooks/hook_process',
    'HookedExitProcess': 'hooks/hook_process',
    'HookedTerminateProcess': 'hooks/hook_process',

    'HookedWaitForSingleObject': 'hooks/hook_wait',
    'HookedWaitForSingleObjectEx': 'hooks/hook_wait',
    'HookedWaitForMultipleObjects': 'hooks/hook_wait',
    'InitWaitHooks': 'hooks/hook_wait',

    'FindFakeParam': 'hooks/hook_netmarble',
    'HookedNMRunSetParam': 'hooks/hook_netmarble',
    'HookedNMRunSetParam2': 'hooks/hook_netmarble',
    'HookedNMRunLoad': 'hooks/hook_netmarble',
    'HookedNMRunGetParam': 'hooks/hook_netmarble',
    'HookedNMRunExistsParam': 'hooks/hook_netmarble',
    'HookedNMRunGetParamCount': 'hooks/hook_netmarble',
    'HookedNMRunRunProg': 'hooks/hook_netmarble',
    'InitNMRunParamLauncherHooks': 'hooks/hook_netmarble',
    'InitNMRunParamGameHooks': 'hooks/hook_netmarble',

    'HookedGetCommandLineA': 'hooks/hook_cmdline',
    'HookedGetCommandLineW': 'hooks/hook_cmdline',
    'InitCmdLineHooks': 'hooks/hook_cmdline',

    'HookedConnect': 'hooks/hook_network',
    'HookedGethostbyname': 'hooks/hook_network',
    'HookedGetaddrinfo': 'hooks/hook_network',
    'InitNetworkHooks': 'hooks/hook_network',

    'HookedRegisterClassExA': 'hooks/hook_window',
    'HookedRegisterClassExW': 'hooks/hook_window',
    'HookedCreateWindowExA': 'hooks/hook_window',
    'HookedCreateWindowExW': 'hooks/hook_window',
    'InitWindowAuditHooks': 'hooks/hook_window',

    'HookedBT_SaveSnapshot': 'hooks/hook_bugtrap',
    'HookedBT_SendSnapshot': 'hooks/hook_bugtrap',
    'HookedBT_SetFlags': 'hooks/hook_bugtrap',
    'InitBugTrapHooks': 'hooks/hook_bugtrap',

    'SetHardwareBreakpointAllThreads': 'bypass/hwbp',
    'ClearHardwareBreakpointAllThreads': 'bypass/hwbp',
    'DumpThreadEips': 'bypass/hwbp',
    'ClassifyEip': 'bypass/hwbp',

    'VehHandler': 'bypass/veh_handler',

    'FakeMessageBoxW': 'bypass/anticheat',
    'FindGGDialogProc': 'bypass/anticheat',
    'DialogKillerThread': 'bypass/anticheat',
    
    'PatchThread': 'main/patcher_main',
    'DllMain': 'main/patcher_main',
}

modules = {}

globals_lines = lines[:126] # up to InitDebugConsole
# let's write out globals.h
with open('core/globals.h', 'w', encoding='utf-8') as f:
    f.write("#pragma once\n")
    # clean up static so we can share them
    for line in globals_lines:
        line = line.replace('static char ', 'extern char ')
        line = line.replace('static const DWORD ', 'extern const DWORD ')
        line = line.replace('static BYTE* ', 'extern BYTE* ')
        line = line.replace('static volatile LONG ', 'extern volatile LONG ')
        line = line.replace('static PVOID ', 'extern PVOID ')
        line = line.replace('static DWORD ', 'extern DWORD ')
        line = line.replace('static HANDLE ', 'extern HANDLE ')
        
        # remove initializers
        if 'extern ' in line and '=' in line and not 'extern "C"' in line:
            line = line[:line.find('=')].strip() + ";\n"
        f.write(line)

with open('core/globals.cpp', 'w', encoding='utf-8') as f:
    f.write('#include "globals.h"\n\n')
    for line in globals_lines:
        if line.startswith('static '):
            line = line.replace('static ', '')
            f.write(line)

# create files
for mod in set(module_map.values()):
    if mod not in modules:
        modules[mod] = []

for i, line in enumerate(lines):
    m = re.match(r'^(static|void|int|DWORD|BOOL|LONG|__declspec|extern "C"|HRESULT)\s+([\w\*]+(?:\s+WINAPI|\s+CALLBACK|\s+WSAAPI|\s+__stdcall|\s+__cdecl)?\s+)?([\w]+)\s*\(', line)
    if m:
        func_name = m.group(3)
        if func_name in module_map:
            start, end = get_block(i)
            if start is not None and end is not None:
                body = "".join(lines[start:end+1])
                # remove 'static ' from function definition if it is there
                if body.startswith('static '):
                    body = body[7:]
                modules[module_map[func_name]].append((func_name, body, "".join(lines[start:i])))

for mod, funcs in modules.items():
    h_file = mod + '.h'
    cpp_file = mod + '.cpp'
    
    with open(h_file, 'w', encoding='utf-8') as fh:
        fh.write('#pragma once\n#include "../core/globals.h"\n\n')
        for fname, body, pre in funcs:
            # extract signature
            sig = body[:body.find('{')].strip()
            # clean up newlines in sig
            sig = " ".join(sig.split())
            fh.write(sig + ";\n")
            
    with open(cpp_file, 'w', encoding='utf-8') as fc:
        fc.write(f'#include "{os.path.basename(h_file)}"\n\n')
        # Include necessary headers if needed, normally globals has them
        for fname, body, pre in funcs:
            fc.write(body + "\n\n")

print("Splitting done!")
