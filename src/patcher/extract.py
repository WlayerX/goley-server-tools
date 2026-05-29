import re

with open('patcher.cpp', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if re.match(r'^(static|void|int|DWORD|BOOL|LONG|__declspec|extern "C"|HRESULT)\s+[\w\*\s]+\(', line):
        print(f"Line {i+1}: {line.strip()}")
