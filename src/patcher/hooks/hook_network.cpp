#include "hook_network.h"
#include "../core/logger.h"
#include "../core/helpers.h"

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (EnterHook()) {
        char buf[256];
        if (name && namelen >= 8 && name->sa_family == AF_INET) {
            const struct sockaddr_in* in4 = (const struct sockaddr_in*)name;
            const unsigned char* ip = (const unsigned char*)&in4->sin_addr;
            wsprintfA(buf, "ws2.connect %u.%u.%u.%u:%u",
                      ip[0], ip[1], ip[2], ip[3], ntohs(in4->sin_port));
        } else {
            wsprintfA(buf, "ws2.connect sa_family=%d namelen=%d",
                      name ? name->sa_family : -1, namelen);
        }
        Log(buf);
        LeaveHook();
    }
    return g_origConnect(s, name, namelen);
}


int WSAAPI HookedGetaddrinfo(const char* pname, const char* psvc,
                                     const struct addrinfo_fwd* pin,
                                     struct addrinfo_fwd** ppres) {
    if (EnterHook()) {
        char buf[400];
        wsprintfA(buf, "ws2.getaddrinfo('%.220s', '%.32s')",
                  pname ? pname : "<null>", psvc ? psvc : "<null>");
        Log(buf);
        LeaveHook();
    }
    return g_origGetaddrinfo(pname, psvc, pin, ppres);
}



static struct hostent* WSAAPI HookedGethostbyname(const char* name) {
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "ws2.gethostbyname('%.220s')", name ? name : "<null>");
        Log(buf);
        LeaveHook();
    }
    return g_origGethostbyname(name);
}

BOOL InitNetworkHooks() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) return FALSE;
    PVOID p1 = GetProcAddress(hWs2, "connect");
    PVOID p2 = GetProcAddress(hWs2, "gethostbyname");
    PVOID p3 = GetProcAddress(hWs2, "getaddrinfo");
    char buf[256];
    wsprintfA(buf, "Net targets: connect=0x%p gethostbyname=0x%p getaddrinfo=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedConnect,
                                    (LPVOID*)&g_origConnect);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("connect hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "connect hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedGethostbyname,
                                    (LPVOID*)&g_origGethostbyname);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("gethostbyname hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "gethostbyname hook FAILED status=%d", s); Log(buf);
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedGetaddrinfo,
                                    (LPVOID*)&g_origGetaddrinfo);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("getaddrinfo hook ENABLED"); anyOk = TRUE;
        } else {
            wsprintfA(buf, "getaddrinfo hook FAILED status=%d", s); Log(buf);
        }
    }
    return anyOk;
}


