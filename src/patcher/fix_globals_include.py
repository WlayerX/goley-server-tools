with open('core/globals.h', 'r', encoding='utf-8') as f:
    g_h = f.read()
if '#include "helpers_typedefs.h"' not in g_h:
    g_h = '#include "helpers_typedefs.h"\n' + g_h
    with open('core/globals.h', 'w', encoding='utf-8') as f:
        f.write(g_h)
