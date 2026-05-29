#pragma once
#include "../core/globals.h"

struct addrinfo_fwd;

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen);
int WSAAPI HookedGetaddrinfo(const char* pname, const char* psvc, const struct addrinfo_fwd* pin, struct addrinfo_fwd** ppres);
BOOL InitNetworkHooks();
