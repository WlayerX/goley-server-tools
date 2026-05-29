import re
import os

with open('patcher.cpp', 'r', encoding='utf-8') as f:
    patcher_code = f.read()

# Extract all typedefs
typedefs = re.findall(r'^typedef\s+.*?;\s*$', patcher_code, re.MULTILINE)
# Also extract multi-line structs
structs = re.findall(r'^typedef\s+struct\s*\{.*?\}.*?;', patcher_code, re.MULTILINE | re.DOTALL)

with open('globals.txt', 'r', encoding='utf-16le', errors='ignore') as f:
    globals_lines = f.readlines()

new_externs = []
new_defs = []

for line in globals_lines:
    line = line.strip()
    if not line: continue
    
    if line.startswith('static '):
        line = line[7:] # remove 'static '
    
    # It might be `volatile LONG g_launcherMode = 0;`
    # Def:
    new_defs.append(line)
    
    # Extern: remove initialization
    if '=' in line:
        extern_line = 'extern ' + line.split('=')[0].strip() + ';'
    else:
        # e.g. char g_fakeCmdLineA[] = "...";
        extern_line = 'extern ' + line
    
    # special case arrays
    if '[]' in extern_line and '=' in line:
        pass # already handled by split('=')[0] -> extern char g_fakeCmdLineA[]
        
    new_externs.append(extern_line)

with open('core/globals.h', 'a', encoding='utf-8') as f:
    f.write("\n// --- Extracted typedefs and structs ---\n")
    for s in structs:
        if s not in open('core/globals.h').read():
            f.write(s + "\n\n")
    for t in typedefs:
        if t not in open('core/globals.h').read() and 'struct' not in t:
            f.write(t + "\n")
            
    f.write("\n// --- Extracted globals ---\n")
    for e in new_externs:
        # Avoid duplicate declarations
        if e.split()[2].split('[')[0] not in open('core/globals.h').read():
            f.write(e + "\n")

with open('core/globals.cpp', 'a', encoding='utf-8') as f:
    f.write("\n// --- Extracted globals defs ---\n")
    existing = open('core/globals.cpp').read()
    for d in new_defs:
        var_name = d.split()[1] if not d.startswith('volatile') else d.split()[2]
        var_name = var_name.split('[')[0]
        if var_name not in existing:
            f.write(d + "\n")

# Now inject includes to patcher_main.cpp
includes = """
#include "../core/logger.h"
#include "../core/utils.h"
#include "../hooks/hook_utils.h"
#include "../hooks/hook_process.h"
#include "../hooks/hook_wait.h"
#include "../hooks/hook_network.h"
#include "../hooks/hook_cmdline.h"
#include "../hooks/hook_window.h"
#include "../hooks/hook_bugtrap.h"
#include "../hooks/hook_netmarble.h"
#include "../bypass/hwbp.h"
#include "../bypass/veh_handler.h"
#include "../bypass/anticheat.h"
"""
for root, dirs, files in os.walk('.'):
    for name in files:
        if name.endswith('.cpp') and name != 'globals.cpp':
            path = os.path.join(root, name)
            content = open(path, 'r', encoding='utf-8').read()
            if 'logger.h' not in content and 'patcher_main' not in name:
                # Add includes
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('#include "../core/globals.h"\n')
                    f.write(includes + "\n")
                    f.write(content)
            elif 'patcher_main' in name:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(includes + "\n")
                    f.write(content)
