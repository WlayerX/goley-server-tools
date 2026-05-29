#include "logger.h"

void InitDebugConsole() {
    if (g_conHandle != INVALID_HANDLE_VALUE) return;
    if (!AllocConsole()) {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
    }
    g_conHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_conHandle == INVALID_HANDLE_VALUE) return;
    char title[128];
    wsprintfA(title, "revival_patcher.dll - LIVE LOG  [PID=%lu]", GetCurrentProcessId());
    SetConsoleTitleA(title);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hIn, &mode)) {
            mode &= ~0x0040;  // ENABLE_QUICK_EDIT_MODE
            mode |=  0x0080;  // ENABLE_EXTENDED_FLAGS
            SetConsoleMode(hIn, mode);
        }
    }
}


void Log(const char* msg) {
    char timed[1100];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int n = wsprintfA(timed, "[%02d:%02d:%02d.%03d P=%lu] %s\r\n",
                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                      GetCurrentProcessId(), msg);

    if (g_conHandle != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(g_conHandle, timed, n, &w, NULL);
    }

    const char* path = g_logPath[0] ? g_logPath : "patcher.log";
    HANDLE h = CreateFileA(path,
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(h, timed, n, &written, NULL);
        CloseHandle(h);
    }
}


void LogLoadedModulesSnapshot(const char* tag) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("LoadedModules: CreateToolhelp32Snapshot failed");
        return;
    }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    char buf[400];
    wsprintfA(buf, "=== loaded modules snapshot (%s) ===", tag);
    Log(buf);
    int count = 0;
    if (Module32First(hSnap, &me)) {
        do {
            wsprintfA(buf, "  mod[%d] base=0x%p size=0x%X %s",
                      count, me.modBaseAddr, me.modBaseSize, me.szModule);
            Log(buf);
            count++;
        } while (Module32Next(hSnap, &me));
    }
    wsprintfA(buf, "=== %d module(s) total ===", count);
    Log(buf);
    CloseHandle(hSnap);
}


void ResolveLogPath(HMODULE hModule) {
    if (!GetModuleFileNameA(hModule, SELF_DLL_PATH, MAX_PATH)) return;
    char tmp[MAX_PATH];
    lstrcpynA(tmp, SELF_DLL_PATH, MAX_PATH);
    for (int up = 0; up < 3; up++) {
        char* slash = (char*)strrchr(tmp, '\\');
        if (!slash) break;
        *slash = 0;
    }
    if (tmp[0]) {
        wsprintfA(g_logPath, "%s\\patcher.log", tmp);
    }
}
