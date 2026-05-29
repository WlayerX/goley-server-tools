import re

with open('patcher.cpp', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Extract typedef structs properly
struct_pattern = r'typedef\s+struct\s*\{[^}]*\}\s*\w+\s*;'
structs = re.findall(struct_pattern, code)

# 2. Extract multi-line function pointer typedefs properly
# matching 'typedef ... (*...)(...);' over multiple lines
func_ptr_pattern = r'typedef\s+.*?\(\w*\s*\*\w+\)\s*\([^;]*\)\s*;'
func_ptrs = re.findall(func_ptr_pattern, code, re.DOTALL)

# 3. Write to helpers.h
with open('core/helpers.h', 'w', encoding='utf-8') as f:
    f.write('#pragma once\n\n')
    for s in structs:
        f.write(s + '\n\n')
    for fp in func_ptrs:
        f.write(fp + '\n\n')

print("Helpers extracted.")
