#include "anticheat.h"
#include "../core/logger.h"
#include "../core/helpers.h"


BOOL CALLBACK FindGGDialogProc(HWND hWnd, LPARAM lParam) {
    FindData* fd = (FindData*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != fd->ownerPid) return TRUE;

    char title[256] = {0};
    GetWindowTextA(hWnd, title, sizeof(title) - 1);
    if (title[0] == '\0') return TRUE;

    // GameGuard error dialogs use captions like:
    //   "GameGuard Error : 150"
    //   "nProtect GameGuard"
    //   "nProtect GameGuard Error Report"
    // Strict filter: only true GameGuard error dialogs by caption.
    // Goley_ main window has title "ChaguChagu V31927 " so we never touch it.
    if (strstr(title, "GameGuard") != NULL ||
        strstr(title, "nProtect")  != NULL) {
        fd->foundHwnd = hWnd;
        return FALSE;
    }
    return TRUE;
}


DWORD WINAPI DialogKillerThread(LPVOID) {
    DWORD myPid = GetCurrentProcessId();
    int killed = 0;
    while (1) {
        FindData fd = { NULL, myPid };
        EnumWindows(FindGGDialogProc, (LPARAM)&fd);
        if (fd.foundHwnd) {
            char title[256] = {0};
            GetWindowTextA(fd.foundHwnd, title, sizeof(title) - 1);
            char buf[512];
            wsprintfA(buf, "DialogKiller: dismissing hWnd=0x%p title='%s'",
                      fd.foundHwnd, title);
            Log(buf);
            // PostMessage WM_CLOSE is the gentlest dismissal -- equivalent
            // to clicking the X button. Most modal dialogs return IDCANCEL.
            PostMessageA(fd.foundHwnd, WM_CLOSE, 0, 0);
            killed++;
            if (killed > 50) {
                // Safety: if we've killed 50 dialogs, the loop is probably
                // misbehaving (catching the main game window). Stop.
                Log("DialogKiller: too many dismissals, stopping");
                break;
            }
        }
        Sleep(150);  // poll 6-7 Hz
    }
    return 0;
}


