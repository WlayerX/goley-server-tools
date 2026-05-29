import re

with open('core/helpers_typedefs.h', 'r', encoding='utf-8') as f:
    code = f.read()
if 'struct FakeParam' not in code:
    code += '\nstruct FakeParam { const char* key; const char* value; };\n'
    with open('core/helpers_typedefs.h', 'w', encoding='utf-8') as f:
        f.write(code)

with open('core/globals.h', 'r', encoding='utf-8') as f:
    g_h = f.read()
if 'g_inHook' not in g_h:
    g_h += '\nextern volatile LONG g_inHook;\nextern const FakeParam g_fakeParams[5];\n'
    with open('core/globals.h', 'w', encoding='utf-8') as f:
        f.write(g_h)

with open('core/globals.cpp', 'r', encoding='utf-8') as f:
    g_cpp = f.read()
if 'g_inHook' not in g_cpp:
    g_cpp += '''
volatile LONG g_inHook = 0;
const FakeParam g_fakeParams[5] = {
    {"GAME_ACCOUNT", "test_account"},
    {"GAME_PASSWORD", "12345"},
    {"LANGUAGE", "TR"},
    {"REGION", "TURKEY"},
    {NULL, NULL}
};
'''
    with open('core/globals.cpp', 'w', encoding='utf-8') as f:
        f.write(g_cpp)

with open('core/helpers.h', 'r', encoding='utf-8') as f:
    h_h = f.read()
if 'HookedExitProcess' not in h_h:
    h_h += '\nVOID WINAPI HookedExitProcess(UINT uExitCode);\nBOOL WINAPI HookedTerminateProcess(HANDLE hProc, UINT uExitCode);\n'
    with open('core/helpers.h', 'w', encoding='utf-8') as f:
        f.write(h_h)
