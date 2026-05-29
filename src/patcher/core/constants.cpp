#include "constants.h"

// --- Themida validation bypass RVAs ---
const DWORD VALIDATION_RVA         = 0x93DC4D;
const DWORD SUCCESS_RVA            = 0x93DCF2;

// --- GameGuard result patch ---
const DWORD GG_RESULT_PATCH_RVA    = 0x935379;  // 0xD35379 (mov esi, eax)
const DWORD GG_OK_STATUS           = 0x755;

// --- GameGuard CreateProcess call ---
const DWORD GG_CREATEPROC_CALL_RVA = 0x4E5A19;  // 0x8E5A19 - 0x400000

// --- MessageBoxW call site ---
const DWORD GG_MBW_CALL_RVA       = 0x935586;
const DWORD GG_MBW_CALL_NEXT_RVA  = 0x93558B;

// --- IAT slot for diagnostics ---
const DWORD GOLEY_MBW_IAT_VA      = 0x019984D4;

// --- Fake parameter table ---
const FakeParam g_fakeParams[] = {
    { "USER_ID",           "goley_test" },
    { "USER_PW",           "test_pw_12345" },
    { "USERID",            "goley_test" },
    { "USERPW",            "test_pw_12345" },
    { "SERVER_IP",         "127.0.0.1" },
    { "SERVERIP",          "127.0.0.1" },
    { "ENTRY_IP",          "127.0.0.1" },
    { "LOGIN_IP",          "127.0.0.1" },
    { "SERVICE",           "1" },
    { "ServiceID",         "1" },
    { "OverrideLanguage",  "tr" },
    { "OverrideLangua",    "tr" },
    { "LangCode",          "tr" },
    { "Region",            "TR" },
    { "GameCode",          "Goley" },
    { "session",           "fake_session_token_abc123" },
    { "Session",           "fake_session_token_abc123" },
    { "Token",             "fake_session_token_abc123" },
    { "AuthToken",         "fake_session_token_abc123" },
    { NULL, NULL }
};

const char* FindFakeParam(const char* key) {
    if (!key) return NULL;
    for (int i = 0; g_fakeParams[i].key; i++) {
        if (lstrcmpiA(key, g_fakeParams[i].key) == 0) {
            return g_fakeParams[i].value;
        }
    }
    return NULL;
}
