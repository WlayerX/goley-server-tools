#include "hook_netmarble.h"
#include "../core/logger.h"
#include "../core/helpers.h"

int __cdecl HookedNMRunSetParam(void* hData, const char* key, const char* value) {
    InterlockedIncrement(&g_nmrunSetParamHits);
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.SetParam #%ld hData=0x%p key='%.80s' value='%.400s'",
                  g_nmrunSetParamHits, hData,
                  key ? key : "<null>", value ? value : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunSetParam) return g_origNMRunSetParam(hData, key, value);
    return 0;
}


int __cdecl HookedNMRunSetParam2(void* hData, int idx, const char* value) {
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.SetParam2 hData=0x%p idx=%d value='%.400s'",
                  hData, idx, value ? value : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunSetParam2) return g_origNMRunSetParam2(hData, idx, value);
    return 0;
}


int __cdecl HookedNMRunLoad(void* hData, int flag, int extra) {
    int rc = 1;  // assume fail
    if (g_origNMRunLoad) rc = g_origNMRunLoad(hData, flag, extra);
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "NMRun.Load(hData=0x%p, flag=%d) -> orig=%d", hData, flag, rc);
        Log(buf);
        LeaveHook();
    }
    // Eger orig fail donduyse: Goley_'in hData'sini bizim onceden
    // yarattigimiz fake-populated hData ile DEGISTIR. Bunun icin caller
    // genelde "out param" donmuyor (cdecl, hData zaten passed-in). hData
    // pointer iyse, biz oraya OUR hData'nin BYTE'larini overlay etmeliyiz.
    // Bu cok riskli; simdilik sadece return value'yu 0 (success) yap ve
    // umalim ki Goley_ "success" branch'inda KULLANDIGI hData zaten OK.
    if (rc != 0 && g_fakeHData) {
        if (EnterHook()) {
            char b[200];
            wsprintfA(b, "  Load fail, fake hData'yi kullanmak icin force 0 ret");
            Log(b);
            LeaveHook();
        }
        // hData içeriğini bizim fake-state ile overlay (deneysel; eger crash
        // verirse orig fail durumuna düş)
        return 1;  // forward orig fail -- guvenli yol
    }
    return rc;
}


int __cdecl HookedNMRunGetParam(void* hData, const char* key, void* outBuf) {
    LONG hits = InterlockedIncrement(&g_nmrunGetParamHits);
    if (hits <= 50 && EnterHook()) {
        char buf[400];
        wsprintfA(buf, "NMRun.GetParam #%ld(hData=0x%p, key='%.80s', outBuf=0x%p)",
                  hits, hData, key ? key : "<null>", outBuf);
        Log(buf);
        LeaveHook();
    }
    int rc = 0;
    if (g_origNMRunGetParam) rc = g_origNMRunGetParam(hData, key, outBuf);
    // Bizim fake string'i outBuf'a yaz (eger orig fail dondurduyse)
    const char* fake = FindFakeParam(key);
    if (fake && outBuf && rc != 0) {
        // outBuf char* mı pointer-to-char*-pointer mı belirsiz; ikisini de
        // dene defansif:
        __try {
            strcpy_s((char*)outBuf, 256, fake);
            if (EnterHook()) {
                char b[200];
                wsprintfA(b, "  -> FAKE wrote '%.60s' to outBuf=0x%p", fake, outBuf);
                Log(b);
                LeaveHook();
            }
            rc = 0;  // success
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // outBuf yazilamaz; orig'in donus degerini birak
        }
    }
    return rc;
}


int __cdecl HookedNMRunExistsParam(void* hData, const char* key) {
    int rc = 0;
    if (g_origNMRunExistsParam) rc = g_origNMRunExistsParam(hData, key);
    if (EnterHook()) {
        char buf[300];
        wsprintfA(buf, "NMRun.ExistsParam('%.80s') -> %d (orig)", key ? key : "<null>", rc);
        Log(buf);
        LeaveHook();
    }
    // FakeParam tablomuzdaki key'leri "var" olarak gosterelim
    if (rc == 0 && FindFakeParam(key)) return 1;
    return rc;
}


int __cdecl HookedNMRunGetParamCount(void* hData) {
    int rc = 0;
    if (g_origNMRunGetCount) rc = g_origNMRunGetCount(hData);
    return rc;
}


int __cdecl HookedNMRunRunProg(void* hData, const char* exe, const char* args) {
    if (EnterHook()) {
        char buf[640];
        wsprintfA(buf, "NMRun.RunProgram hData=0x%p exe='%.200s' args='%.400s'",
                  hData, exe ? exe : "<null>", args ? args : "<null>");
        Log(buf);
        LeaveHook();
    }
    if (g_origNMRunRunProg) return g_origNMRunRunProg(hData, exe, args);
    return 0;
}


BOOL InitNMRunParamLauncherHooks() {
    HMODULE hMod = GetModuleHandleA("NMRunParamDLL.dll");
    if (!hMod) return FALSE;  // launcher henuz yuklemedi; tekrar dene
    PVOID p1 = GetProcAddress(hMod, "NMRunParamDLL_SetParam");
    PVOID p2 = GetProcAddress(hMod, "NMRunParamDLL_SetParam2");
    PVOID p3 = GetProcAddress(hMod, "NMRunParamDLL_RunProgram");
    char buf[256];
    wsprintfA(buf, "NMRun launcher targets: SetParam=0x%p SetParam2=0x%p RunProgram=0x%p",
              p1, p2, p3);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedNMRunSetParam,
                                    (LPVOID*)&g_origNMRunSetParam);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("  SetParam ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedNMRunSetParam2,
                                    (LPVOID*)&g_origNMRunSetParam2);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("  SetParam2 ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedNMRunRunProg,
                                    (LPVOID*)&g_origNMRunRunProg);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("  RunProgram ENABLED (observer)"); anyOk = TRUE;
        }
    }
    if (anyOk) Log("(Launcher mode -- Load/GetParam fake yok)");
    return anyOk;
}


BOOL InitNMRunParamGameHooks() {
    HMODULE hMod = GetModuleHandleA("NMRunParamDLL.dll");
    if (!hMod) {
        // Game client'da Themida launcher'siz spawn icin fake param store
        // gerek. Bu game-only davranis.
        hMod = LoadLibraryA("C:\\Joygame\\Goley\\BinaryTr\\NMRunParamDLL.dll");
        if (hMod) Log("NMRunParamDLL pre-loaded by patcher (game mode)");
        else      Log("NMRunParamDLL.dll bulunamadi");
        if (!hMod) return FALSE;
    }
    PVOID p1 = GetProcAddress(hMod, "NMRunParamDLL_SetParam");
    PVOID p2 = GetProcAddress(hMod, "NMRunParamDLL_SetParam2");
    PVOID p3 = GetProcAddress(hMod, "NMRunParamDLL_RunProgram");
    PVOID p4 = GetProcAddress(hMod, "NMRunParamDLL_Load");
    PVOID p5 = GetProcAddress(hMod, "NMRunParamDLL_GetParam");
    PVOID p6 = GetProcAddress(hMod, "NMRunParamDLL_ExistsParam");
    PVOID p7 = GetProcAddress(hMod, "NMRunParamDLL_GetParamCount");
    char buf[400];
    wsprintfA(buf, "NMRun game targets: SetParam=0x%p SetParam2=0x%p RunProgram=0x%p", p1, p2, p3);
    Log(buf);
    wsprintfA(buf, "NMRun game targets: Load=0x%p GetParam=0x%p ExistsParam=0x%p GetParamCount=0x%p",
              p4, p5, p6, p7);
    Log(buf);
    BOOL anyOk = FALSE;
    if (p1) {
        MH_STATUS s = MH_CreateHook(p1, (LPVOID)&HookedNMRunSetParam,
                                    (LPVOID*)&g_origNMRunSetParam);
        if (s == MH_OK && MH_EnableHook(p1) == MH_OK) {
            Log("NMRun.SetParam hook ENABLED"); anyOk = TRUE;
        }
    }
    if (p2) {
        MH_STATUS s = MH_CreateHook(p2, (LPVOID)&HookedNMRunSetParam2,
                                    (LPVOID*)&g_origNMRunSetParam2);
        if (s == MH_OK && MH_EnableHook(p2) == MH_OK) {
            Log("NMRun.SetParam2 hook ENABLED"); anyOk = TRUE;
        }
    }
    if (p3) {
        MH_STATUS s = MH_CreateHook(p3, (LPVOID)&HookedNMRunRunProg,
                                    (LPVOID*)&g_origNMRunRunProg);
        if (s == MH_OK && MH_EnableHook(p3) == MH_OK) {
            Log("NMRun.RunProgram hook ENABLED"); anyOk = TRUE;
        }
    }
    struct HSpec { PVOID target; LPVOID detour; LPVOID* orig; const char* name; };
    HSpec specs[] = {
        { p4, (LPVOID)&HookedNMRunLoad,          (LPVOID*)&g_origNMRunLoad,        "NMRun.Load" },
        { p5, (LPVOID)&HookedNMRunGetParam,      (LPVOID*)&g_origNMRunGetParam,    "NMRun.GetParam" },
        { p6, (LPVOID)&HookedNMRunExistsParam,   (LPVOID*)&g_origNMRunExistsParam, "NMRun.ExistsParam" },
        { p7, (LPVOID)&HookedNMRunGetParamCount, (LPVOID*)&g_origNMRunGetCount,    "NMRun.GetParamCount" },
    };
    for (int i = 0; i < (int)(sizeof(specs)/sizeof(specs[0])); i++) {
        if (!specs[i].target) continue;
        MH_STATUS s = MH_CreateHook(specs[i].target, specs[i].detour, specs[i].orig);
        if (s == MH_OK && MH_EnableHook(specs[i].target) == MH_OK) {
            char b[200];
            wsprintfA(b, "%s hook ENABLED (FAKE param mode)", specs[i].name);
            Log(b);
            anyOk = TRUE;
        }
    }
    return anyOk;
}


