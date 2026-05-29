import re

with open('core/helpers_typedefs.h', 'r', encoding='utf-8') as f:
    code = f.read()

# Add WIN32_LEAN_AND_MEAN
if 'WIN32_LEAN_AND_MEAN' not in code:
    code = code.replace('#include <winsock2.h>', '#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n#include <winsock2.h>')

# Fix BT_SetFlags_t
code = code.replace('typedef int (__stdcall *BT_SetFlags_t)(int flags);', 'typedef void (__stdcall *BT_SetFlags_t)(DWORD flags);')

with open('core/helpers_typedefs.h', 'w', encoding='utf-8') as f:
    f.write(code)

# Fix hook_network.h
with open('hooks/hook_network.h', 'r', encoding='utf-8') as f:
    hcode = f.read()
hcode = hcode.replace('const struct addrinfo_fwd* pin, struct addrinfo_fwd** ppres', 'const ADDRINFOA* pin, PADDRINFOA* ppres')
with open('hooks/hook_network.h', 'w', encoding='utf-8') as f:
    f.write(hcode)

