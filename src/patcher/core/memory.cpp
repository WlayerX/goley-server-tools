#include "memory.h"
#include "logger.h"

BOOL PatchStdcallStub(DWORD funcVA, int retBytes, const char* name) {
    if (!funcVA) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: %s VA is NULL, skipped", name);
        Log(buf);
        return FALSE;
    }
    BYTE patch[8] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,         // mov eax, 1
        0xC2, (BYTE)(retBytes & 0xFF), 0x00    // ret <retBytes>
    };
    DWORD oldProt = 0;
    LPVOID target = (LPVOID)(ULONG_PTR)funcVA;
    if (!VirtualProtect(target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt)) {
        char buf[128];
        wsprintfA(buf, "PatchStdcallStub: VirtualProtect failed for %s (err=%lu)",
                  name, GetLastError());
        Log(buf);
        return FALSE;
    }
    BYTE orig[8];
    memcpy(orig, target, sizeof(orig));
    memcpy(target, patch, sizeof(patch));

    DWORD dummy;
    VirtualProtect(target, sizeof(patch), oldProt, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(patch));

    char buf[256];
    wsprintfA(buf, "Patched %s @ 0x%X  orig=%02X%02X%02X%02X%02X%02X%02X%02X -> mov eax,1 / ret %d",
              name, funcVA,
              orig[0], orig[1], orig[2], orig[3], orig[4], orig[5], orig[6], orig[7],
              retBytes);
    Log(buf);
    return TRUE;
}

BOOL PatchMessageBoxStub(DWORD funcVA, const char* name) {
    return PatchStdcallStub(funcVA, 16, name);  // 4 args
}

BOOL PatchHangStub(DWORD funcVA, const char* name) {
    if (!funcVA) {
        char buf[128];
        wsprintfA(buf, "PatchHangStub: %s VA is NULL, skipped", name);
        Log(buf);
        return FALSE;
    }
    BYTE patch[2] = { 0xEB, 0xFE }; // jmp short -2 (infinite loop)
    DWORD oldProt = 0;
    LPVOID target = (LPVOID)(ULONG_PTR)funcVA;
    if (!VirtualProtect(target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt)) {
        char buf[128];
        wsprintfA(buf, "PatchHangStub: VirtualProtect failed for %s (err=%lu)",
                  name, GetLastError());
        Log(buf);
        return FALSE;
    }
    BYTE orig[2];
    memcpy(orig, target, sizeof(orig));
    memcpy(target, patch, sizeof(patch));

    DWORD dummy;
    VirtualProtect(target, sizeof(patch), oldProt, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(patch));

    char buf[256];
    wsprintfA(buf, "Patched %s @ 0x%X  orig=%02X%02X -> EB FE (hang loop)",
              name, funcVA, orig[0], orig[1]);
    Log(buf);
    return TRUE;
}

int WINAPI FakeMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    char tbuf[256] = {0};
    char cbuf[256] = {0};
    if (lpText) {
        for (int i = 0; i < 255 && lpText[i]; i++)
            tbuf[i] = (lpText[i] < 0x80) ? (char)lpText[i] : '?';
    }
    if (lpCaption) {
        for (int i = 0; i < 255 && lpCaption[i]; i++)
            cbuf[i] = (lpCaption[i] < 0x80) ? (char)lpCaption[i] : '?';
    }
    char buf[1024];
    wsprintfA(buf, "FakeMessageBoxW INTERCEPT: caption='%s' text='%s' type=0x%X -> IDOK",
              cbuf, tbuf, uType);
    Log(buf);
    return 1;  // IDOK
}

int ScanAndReplaceFnPointer(DWORD target, DWORD replacement, const char* name,
                            BOOL dryRun) {
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = (BYTE*)0x00010000;
    BYTE* endAddr = (BYTE*)0x7FFE0000;

    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&ScanAndReplaceFnPointer, &hSelf);
    DWORD selfBase = (DWORD)(ULONG_PTR)hSelf;
    DWORD selfEnd  = selfBase + 0x100000;

    while (addr < endAddr) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x10000;
            continue;
        }
        BOOL skip = (mbi.State != MEM_COMMIT)
                 || (mbi.Protect & PAGE_NOACCESS)
                 || (mbi.Protect & PAGE_GUARD)
                 || (mbi.Protect == PAGE_EXECUTE);

        DWORD regionStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
        if (regionStart >= selfBase && regionStart < selfEnd) skip = TRUE;

        if (!skip) {
            DWORD scanStart = (DWORD)(ULONG_PTR)mbi.BaseAddress;
            DWORD scanEnd   = scanStart + (DWORD)mbi.RegionSize;
            scanStart = (scanStart + 3) & ~3;
            for (DWORD p = scanStart; p + 4 <= scanEnd; p += 4) {
                __try {
                    if (*(DWORD*)(ULONG_PTR)p == target) {
                        found++;
                        if (!dryRun) {
                            DWORD oldProt;
                            if (VirtualProtect((LPVOID)(ULONG_PTR)p, 4, PAGE_READWRITE, &oldProt)) {
                                *(DWORD*)(ULONG_PTR)p = replacement;
                                DWORD dummy;
                                VirtualProtect((LPVOID)(ULONG_PTR)p, 4, oldProt, &dummy);
                                char buf[160];
                                wsprintfA(buf, "  patched %s slot at 0x%X  prot=0x%X",
                                          name, p, mbi.Protect);
                                Log(buf);
                            }
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    char buf[160];
    wsprintfA(buf, "Memory scan for %s (target=0x%X) found %d slot(s) %s",
              name, target, found, dryRun ? "[dry-run]" : "[patched]");
    Log(buf);
    return found;
}

BOOL PatchIATSlot(DWORD slotVA, DWORD newValue, const char* name) {
    DWORD oldProt = 0;
    LPVOID slot = (LPVOID)(ULONG_PTR)slotVA;
    if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &oldProt)) {
        char buf[160];
        wsprintfA(buf, "PatchIATSlot: VirtualProtect failed for %s @ 0x%X (err=%lu)",
                  name, slotVA, GetLastError());
        Log(buf);
        return FALSE;
    }
    DWORD oldVal = *(DWORD*)slot;
    *(DWORD*)slot = newValue;
    DWORD dummy;
    VirtualProtect(slot, sizeof(DWORD), oldProt, &dummy);

    char buf[160];
    wsprintfA(buf, "IAT slot %s @ 0x%X: 0x%X -> 0x%X", name, slotVA, oldVal, newValue);
    Log(buf);
    return TRUE;
}

