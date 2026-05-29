// revival_tool.exe
//
// revival projesinin tek CLI'si. Eskiden bir sürü dağınık PowerShell
// helper'i vardi; hepsi 32-bit tek bir konsol uygulamasında toplandı.
//
// Subcommand'ler:
//
//   revival_tool init <setup.exe>
//                       Joygame setup'ını çalıştırır, kurulum sonrası
//                       Goley_.exe'nin yerini doğrular, IFEO Debugger
//                       kaydını set eder. Bir kerelik işleyiş.
//
//   revival_tool launch
//                       Goley_.exe'yi CREATE_SUSPENDED ile spawn eder,
//                       patcher.dll'i inject eder, ResumeThread çağırır.
//                       Themida'lı orijinal binary için.
//
//   revival_tool launch-unpacked
//                       unpacked_Goley_PATCHED.exe'yi çalıştırır (Themida
//                       yok, DLL inject yok, sadece doğru working dir).
//
//   revival_tool extract [vlh vld]
//                       Şifreli VLH/VLD oyun dosyalarını açar. Argument
//                       verilmezse Goley install dizinindeki Data klasörünün
//                       tamamı işlenir. Python decrypt.py'yi çağırır.
//
//   revival_tool patch <input> <output>
//                       Bir unpacked binary'e patches.json patch'lerini
//                       uygular. Python apply_patches.py'yi çağırır. IDA
//                       gerektirmiyor.
//
//   revival_tool unpack <pid>
//                       Çalışan Goley_'in unpacked PE memory'sini diske
//                       yazar. Themida unpack bittiğinde çalıştırılmalı.
//                       Deneysel.
//
//   revival_tool inject <pid>
//                       Çalışan PID'ye patcher.dll inject eder
//                       (CreateRemoteThread + LoadLibraryA).
//
//   revival_tool dump-threads <pid>
//                       Her thread'in EIP/ESP/return-addr zincirini çıkarır.
//                       32-bit target. EIP'leri modüle göre sınıflar.
//
//   revival_tool ifeo set | clear | show
//                       IFEO Debugger registry kaydını yönet.
//
//   revival_tool cleanup
//                       Asılı kalmış Goley_/wrapper'ları öldürür + IFEO
//                       temizler.
//
//   revival_tool ping     Sanity testi ("ok" yazar).
//   revival_tool help     Komut listesi.
//
// Build: src/tool/build.bat (VS 2022 vcvars32, /MT, /MACHINE:X86)
// Output: revival_tool.exe (32-bit, Goley_ thread context'lerini okumak icin)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// --------------------------------------------------------------------
// Konfigurasyon: hicbir sey hardcoded degil.
//
// Bu .exe nereye konulduysa orasi repo'nun src/tool dizini. Diger
// artefaktlari oradan iki uste cikarak buluruz. Goley'in kurulu oldugu
// yer ise once GOLEY_INSTALL_DIR environment variable'indan, yoksa
// varsayilan C:\Joygame\Goley\BinaryTr'den okunur.
// --------------------------------------------------------------------
#include <string>

static std::string g_repoRoot;
static std::string g_goleyDir;

static std::string DirName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? "." : path.substr(0, pos);
}

// revival_tool.exe iki seviye altta: <repo>/src/tool/revival_tool.exe
// Ondan repo kokunu hesaplariz. Boylece kullanici reponun yerini
// degistirse bile path'ler dogru gelir.
static const std::string& RepoRoot() {
    if (!g_repoRoot.empty()) return g_repoRoot;
    char buf[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    std::string p(buf);
    p = DirName(p);   // .../src/tool
    p = DirName(p);   // .../src
    p = DirName(p);   // .../  <repo root>
    g_repoRoot = p;
    return g_repoRoot;
}

// Goley'in kurulu oldugu klasor. Once environment, sonra varsayilan.
static const std::string& GoleyDir() {
    if (!g_goleyDir.empty()) return g_goleyDir;
    char envBuf[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableA("GOLEY_INSTALL_DIR", envBuf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) g_goleyDir = envBuf;
    else                       g_goleyDir = "C:\\Joygame\\Goley\\BinaryTr";
    return g_goleyDir;
}

namespace cfg {
    static std::string GoleyExe()       { return GoleyDir() + "\\Goley_.exe"; }
    static std::string UnpackedExe()    { return GoleyDir() + "\\unpacked_Goley_PATCHED.exe"; }
    // Launcher (root) -- Goley.exe is one level above GoleyDir (BinaryTr/).
    // Parent of BinaryTr is the install root (typically C:\Joygame\Goley).
    static std::string GoleyRoot()      { return GoleyDir() + "\\.."; }
    static std::string LauncherExe()    { return GoleyRoot() + "\\Goley.exe"; }
    static std::string PatcherDll()     { return RepoRoot() + "\\src\\patcher\\revival_patcher.dll"; }
    static std::string WrapperExe()     { return RepoRoot() + "\\src\\wrapper\\revival_wrapper.exe"; }
    static std::string ApplyPatchesPy() { return RepoRoot() + "\\src\\tool\\apply_patches.py"; }
    static std::string DecryptPy()      { return RepoRoot() + "\\src\\extract\\decrypt.py"; }
    constexpr const char* kIfeoKey   = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Goley_.exe";
    constexpr const char* kIfeoValue = "Debugger";
}

// --------------------------------------------------------------------
// Yardimcilar: log, admin check
// --------------------------------------------------------------------
static void info(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}
static void err(const char* fmt, ...) {
    fputs("ERR: ", stderr);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// Current token Administrators grubunda mi?
// Goley_'in manifest'i requireAdministrator, neredeyse her subcommand
// admin gerektirir.
static bool IsRunningAsAdmin(void) {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

static void WarnIfNotAdmin(const char* needed_for) {
    if (!IsRunningAsAdmin()) {
        err("Administrator olarak calismiyor. %s ACCESS_DENIED verebilir.", needed_for);
        err("cmd.exe'yi sag tikla, Yonetici olarak Calistir, sonra tekrar dene.");
    }
}

// --------------------------------------------------------------------
// PID arama yardimcilari
// --------------------------------------------------------------------
// Process adlari `prefix` ile baslayanlarin PID listesini cikar.
// `cleanup` PID istemiyor, kendi buluyor.
static std::vector<DWORD> FindPidsByPrefix(const char* prefix) {
    std::vector<DWORD> hits;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return hits;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_strnicmp(pe.szExeFile, prefix, lstrlenA(prefix)) == 0) {
                hits.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return hits;
}

// --------------------------------------------------------------------
// IFEO Debugger kaydi yonetimi
// --------------------------------------------------------------------
// nProtect "trusted re-launch" pattern'i Goley_.exe'yi child olarak
// tekrar spawn ediyor. IFEO olmadan o child *bizim DLL'imiz olmadan*
// calisir. IFEO Debugger revival_wrapper.exe'yi gosterirse, her
// CreateProcess(Goley_) bizim uzerimizden gecer ve child'a da DLL
// inject ederiz.
static int IfeoSetDebuggerForImage(const char* imageFileName) {
    char keyPath[512];
    _snprintf_s(keyPath, sizeof(keyPath), _TRUNCATE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                "Image File Execution Options\\%s", imageFileName);
    HKEY key = NULL;
    DWORD disp = 0;
    LSTATUS r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                NULL, &key, &disp);
    if (r != ERROR_SUCCESS) {
        err("RegCreateKeyExA(%s) failed: %ld", imageFileName, r);
        return 1;
    }
    std::string val = "\""; val += cfg::WrapperExe().c_str(); val += "\"";
    r = RegSetValueExA(key, cfg::kIfeoValue, 0, REG_SZ,
                       (const BYTE*)val.c_str(), (DWORD)val.size() + 1);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) {
        err("RegSetValueExA(%s) failed: %ld", imageFileName, r);
        return 1;
    }
    info("IFEO Debugger set for %s -> %s", imageFileName, val.c_str());
    return 0;
}

static int CmdIfeoSet(void) {
    WarnIfNotAdmin("HKLM yazma");
    if (IfeoSetDebuggerForImage("Goley_.exe") != 0) return 1;
    // STUB (Goley_.exe) spawns BinaryTr.bin payload; same wrapper inject path.
    if (IfeoSetDebuggerForImage("BinaryTr.bin") != 0) return 1;
    return 0;
}

static int CmdIfeoClear(void) {
    WarnIfNotAdmin("HKLM yazma");
    HKEY key = NULL;
    LSTATUS r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, cfg::kIfeoKey, 0,
                              KEY_SET_VALUE, &key);
    if (r != ERROR_SUCCESS) {
        info("IFEO key yok (zaten temiz)");
        return 0;
    }
    LSTATUS r2 = RegDeleteValueA(key, cfg::kIfeoValue);
    RegCloseKey(key);
    info("IFEO Debugger temizlendi (RegDeleteValue: %ld)", r2);
    return 0;
}

static int CmdIfeoShow(void) {
    HKEY key = NULL;
    LSTATUS r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, cfg::kIfeoKey, 0,
                              KEY_QUERY_VALUE, &key);
    if (r != ERROR_SUCCESS) { info("IFEO key yok."); return 0; }
    char buf[1024]; DWORD sz = sizeof(buf); DWORD type = 0;
    r = RegQueryValueExA(key, cfg::kIfeoValue, NULL, &type, (LPBYTE)buf, &sz);
    RegCloseKey(key);
    if (r == ERROR_SUCCESS) info("IFEO Debugger = %s", buf);
    else                    info("IFEO key var ama Debugger value yok.");
    return 0;
}

// --------------------------------------------------------------------
// DLL injection (CreateRemoteThread + LoadLibraryA)
// --------------------------------------------------------------------
// SELF_DLL_PATH'i target process'e kopyalar, LoadLibraryA(path) cagiran
// bir thread spawn eder. Hem calisan hem CREATE_SUSPENDED target'larda
// kernel32 map'lendigi surece calisir.

// Target process module listesinde verilen basename'i ara (case-insensitive).
// Toolhelp32 SNAPMODULE32 ile 32-bit hedef icin de calisir.
static bool VerifyModuleLoaded(DWORD pid, const char* basename) {
    DWORD flags = 0x00000008 | 0x00000010; // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    for (int retry = 0; retry < 10; ++retry) {
        HANDLE snap = CreateToolhelp32Snapshot(flags, pid);
        if (snap == INVALID_HANDLE_VALUE) {
            if (GetLastError() == 24) { Sleep(50); continue; }
            return false;
        }
        MODULEENTRY32 me = { sizeof(me) };
        bool found = false;
        if (Module32First(snap, &me)) {
            do {
                if (lstrcmpiA(me.szModule, basename) == 0) { found = true; break; }
                me.dwSize = sizeof(me);
            } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
        return found;
    }
    return false;
}

static bool InjectIntoProcess(HANDLE hProcess, DWORD pid, const char* dllPath) {
    SIZE_T pathBytes = lstrlenA(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProcess, NULL, pathBytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { err("VirtualAllocEx failed: %lu", GetLastError()); return false; }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote, dllPath, pathBytes, &written)) {
        err("WriteProcessMemory failed: %lu", GetLastError()); return false;
    }
    HMODULE k = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(k, "LoadLibraryA");
    if (!pLoadLib) { err("GetProcAddress(LoadLibraryA) failed"); return false; }
    HANDLE thr = CreateRemoteThread(hProcess, NULL, 0, pLoadLib, remote, 0, NULL);
    if (!thr) { err("CreateRemoteThread failed: %lu", GetLastError()); return false; }
    WaitForSingleObject(thr, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(thr, &exitCode);
    CloseHandle(thr);

    // exitCode yorumu:
    //   * NTSTATUS exception code (0xC0000XXX, 0x80000XXX) -> thread CRASHED
    //   * 0                                                 -> LoadLibrary fail
    //   * (HMODULE 32-bit)                                  -> success
    bool isException = ((exitCode & 0xF0000000) == 0xC0000000) ||
                       ((exitCode & 0xF0000000) == 0x80000000);
    if (isException) {
        info("  LoadLibrary remote thread CRASHED with NTSTATUS 0x%08lX", exitCode);
    } else if (exitCode == 0) {
        info("  LoadLibrary returned NULL -- load FAILED");
    } else {
        info("  LoadLibrary returned 0x%08lX (HMODULE)", exitCode);
    }

    // Asil success kriteri: module list'te revival_patcher.dll var mi?
    // Module list'in fill olmasi icin biraz bekle (yeni baslayan process'de).
    Sleep(200);
    const char* base = strrchr(dllPath, '\\');
    base = base ? base + 1 : dllPath;
    bool loaded = VerifyModuleLoaded(pid, base);
    info("  Module verify (%s): %s", base, loaded ? "LOADED OK" : "NOT FOUND");
    return loaded;
}

static int CmdInject(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool inject <pid>"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[2], NULL, 0);
    if (!pid) { err("hatali pid: %s", argv[2]); return 1; }
    WarnIfNotAdmin("Goley_ icin OpenProcess (requireAdministrator manifest)");
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) { err("OpenProcess(%lu) failed: %lu", pid, GetLastError()); return 1; }
    info("Inject ediliyor %s -> PID %lu...", cfg::PatcherDll().c_str(), pid);
    bool ok = InjectIntoProcess(h, pid, cfg::PatcherDll().c_str());
    CloseHandle(h);
    return ok ? 0 : 1;
}

// --------------------------------------------------------------------
// launch akisi (paylasimli)
// --------------------------------------------------------------------
static int LaunchAndInject(const char* exePath, const char* workDir,
                            const char* extraArgs = NULL) {
    WarnIfNotAdmin("Goley_.exe manifest requireAdministrator");
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    info("Spawn ediliyor %s (CREATE_SUSPENDED)...", exePath);
    // CreateProcessA lpCommandLine: argv[0] = exe, sonra args.
    // lpCommandLine MUTABLE olmali. Buffer hazirla.
    char cmdLine[1024];
    if (extraArgs && *extraArgs) {
        _snprintf_s(cmdLine, sizeof(cmdLine), _TRUNCATE,
                    "\"%s\" %s", exePath, extraArgs);
        info("  cmdline=%s", cmdLine);
    } else {
        _snprintf_s(cmdLine, sizeof(cmdLine), _TRUNCATE, "\"%s\"", exePath);
    }
    if (!CreateProcessA(exePath, cmdLine, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, workDir, &si, &pi)) {
        err("CreateProcessA failed: %lu (740 = elevation required)", GetLastError());
        return 1;
    }
    info("  PID=%lu, ana thread suspended", pi.dwProcessId);
    info("patcher.dll inject ediliyor...");
    if (!InjectIntoProcess(pi.hProcess, pi.dwProcessId, cfg::PatcherDll().c_str())) {
        err("Inject basarisiz. Child sonlandiriliyor.");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    DWORD prev = ResumeThread(pi.hThread);
    info("ResumeThread returned %lu - child calisiyor.", prev);
    info("PID %lu senin. patcher.log dosyasini izle.", pi.dwProcessId);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

static int CmdLaunch(void) {
    // IFEO aktifken CreateProcess(Goley_.exe) dogrudan wrapper'i calistirir;
    // patcher'i Goley_'e tool inject etmez (yanlis PID). Wrapper Goley_'i
    // DEBUG_PROCESS ile spawn edip inject eder (THEMIDA_BYPASS.md sira).
    WarnIfNotAdmin("IFEO + wrapper launch");
    if (CmdIfeoSet() != 0) return 1;

    const std::string& wrapper = cfg::WrapperExe();
    const std::string& goley   = cfg::GoleyExe();
    char cmdline[1024];
    _snprintf_s(cmdline, sizeof(cmdline), _TRUNCATE,
                "\"%s\" \"%s\"", wrapper.c_str(), goley.c_str());

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    info("Wrapper ile baslatiliyor (IFEO -> tek Goley_ child + inject):");
    info("  %s", cmdline);
    if (!CreateProcessA(wrapper.c_str(), cmdline, NULL, NULL, FALSE,
                        0, NULL, GoleyDir().c_str(), &si, &pi)) {
        err("CreateProcessA(wrapper) failed: %lu", GetLastError());
        return 1;
    }
    info("wrapper PID=%lu -- patcher.log + wrapper.log izle", pi.dwProcessId);
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    info("wrapper bitti, exit code=%lu", ec);
    return (ec == 0) ? 0 : 1;
}

static int CmdLaunchUnpacked(void) {
    // Statik patch yolu: Themida yok. CREATE_SUSPENDED + immediate inject
    // unpacked binary'de loader bitmemis kernel32 ile AV veriyor. Onun
    // yerine ciplak baslat + 3 sn bekle + late inject.
    const char* exePath = cfg::UnpackedExe().c_str();
    const char* workDir = GoleyDir().c_str();
    info("Naked spawn (no suspend) %s...", exePath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                        0, NULL, workDir, &si, &pi)) {
        err("CreateProcessA failed: %lu", GetLastError());
        return 1;
    }
    info("  PID=%lu", pi.dwProcessId);
    info("3 sn bekleniyor (loader/CRT tamamlasin)...");
    Sleep(3000);
    info("Inject ediliyor...");
    if (!InjectIntoProcess(pi.hProcess, pi.dwProcessId, cfg::PatcherDll().c_str())) {
        err("Inject basarisiz");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    info("PID %lu senin. patcher.log dosyasini izle.", pi.dwProcessId);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

// launch-args <args>: Goley_.exe + patcher.dll inject + custom args.
// Args ornek: "TrAuth NoPopup", "TrAuth foo.txt NoPopup"
// WinMain icin a3=lpCmdLine = exe path sonrasi her sey.
static int CmdLaunchArgs(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool launch-args \"<lpCmdLine>\""); return 1; }
    // Tum kalan argument'lari birlestir
    std::string combined;
    for (int i = 2; i < argc; i++) {
        if (i > 2) combined += " ";
        combined += argv[i];
    }
    info("Args: %s", combined.c_str());
    CmdIfeoSet();
    return LaunchAndInject(cfg::GoleyExe().c_str(), GoleyDir().c_str(),
                           combined.c_str());
}

// launch-launcher: Goley.exe (root launcher) + patcher.dll inject.
// Themida unpack + NMRunParamDLL_SetParam hook'lari calistirilir. Amac:
// launcher Goley_.exe spawn etmeden once tum (key, value) param'larini
// patcher.log'a doken. Boylece server emulator hangi key'leri beklemesi
// gerek bilir, ileride bizim "launch-with-fake-params" yolunu yazariz.
static int CmdLaunchLauncher(void) {
    // Themida'li launcher icin child re-exec'i de wrapper'a yonlendir.
    CmdIfeoSet();
    return LaunchAndInject(cfg::LauncherExe().c_str(), cfg::GoleyRoot().c_str());
}

// --------------------------------------------------------------------
// init: setup.exe'yi calistir + IFEO ayarla + duzeni hazirla
// --------------------------------------------------------------------
// Joygame setup'i tipik bir InstallShield/NSIS tarzi installer. Silent
// install'u "/S" veya "/silent" bayraklariyla denenir, basarisiz olursa
// kullanici GUI installer'i tamamlar.
static int CmdInit(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool init <setup.exe yolu>"); return 1; }
    const char* setupPath = argv[2];

    if (GetFileAttributesA(setupPath) == INVALID_FILE_ATTRIBUTES) {
        err("setup bulunamadi: %s", setupPath);
        return 1;
    }
    WarnIfNotAdmin("setup install Program Files yazabilir");

    info("[1/4] Setup calistiriliyor: %s", setupPath);
    info("       (Silent mode denenmiyor; setup GUI'si acilirsa tamamla, sonra cikis)");
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "open";
    sei.lpFile = setupPath;
    sei.nShow  = SW_SHOWNORMAL;
    if (!ShellExecuteExA(&sei)) {
        err("ShellExecuteEx failed: %lu", GetLastError()); return 1;
    }
    info("       Setup baslatildi. Tamamlanmasi bekleniyor...");
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        info("       Setup exit code: %lu", exitCode);
    }

    std::string goleyExe = cfg::GoleyExe();
    info("[2/4] Goley_.exe yerinde mi kontrol ediliyor: %s", goleyExe.c_str());
    if (GetFileAttributesA(goleyExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err("Goley_.exe bulunamadi. Setup'in dogru klasore kurdugundan emin ol:");
        err("  beklenen: %s", goleyExe.c_str());
        err("  Eger setup'u farkli bir klasore kurduysan, GOLEY_INSTALL_DIR");
        err("  environment variable'i ile yeni klasoru goster:");
        err("    set GOLEY_INSTALL_DIR=D:\\Oyunlar\\Goley\\BinaryTr");
        err("  sonra `revival_tool init` komutunu tekrar calistir.");
        return 1;
    }
    info("       Bulundu.");

    info("[3/4] IFEO Debugger kaydi ayarlaniyor...");
    if (CmdIfeoSet() != 0) {
        err("IFEO kaydi basarisiz. Manuel: revival_tool ifeo set");
        return 1;
    }

    info("[4/4] Hazir. Asagidaki komut ile client'i baslat:");
    info("       revival_tool launch");
    return 0;
}

// --------------------------------------------------------------------
// extract: VLH/VLD oyun dosyalarini cozer (Python script'i cagrilir)
// --------------------------------------------------------------------
// Goley oyun datasini Anipark'in kendi cipher'i ile sifrelemis.
// src/extract/decrypt.py Goley'in kendi decrypt fonksiyonunu Unicorn
// emulator'de calistirarak Character.VLH/VLD, Stadium.VLH/VLD,
// Translations.VLH/VLD gibi cift'leri aciyor.
//
// Kullanim:
//   revival_tool extract                            (data klasorunun tamami)
//   revival_tool extract <vlh> [vld] [--out DIR]   (tek cift)
static int CmdExtract(int argc, char** argv) {
    std::string cmdline = "python \"";
    cmdline += cfg::DecryptPy();
    cmdline += "\"";

    if (argc < 3) {
        // Argument verilmemisse: Goley install dizinindeki Data klasorunu
        // tamamen acmaya calis.
        std::string dataDir = GoleyDir();
        // BinaryTr -> Data icin bir seviye yukari cik
        size_t pos = dataDir.find_last_of("\\/");
        if (pos != std::string::npos) {
            dataDir = dataDir.substr(0, pos) + "\\Data";
        }
        cmdline += " --all \"" + dataDir + "\"";
    } else {
        // Argumentleri oldugu gibi gectir
        for (int i = 2; i < argc; i++) {
            cmdline += " \"";
            cmdline += argv[i];
            cmdline += "\"";
        }
    }

    info("calistiriliyor: %s", cmdline.c_str());

    std::vector<char> cmd(cmdline.begin(), cmdline.end());
    cmd.push_back(0);
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        err("python basarisiz: %lu (Python 3 PATH'te mi? `pip install unicorn` calistirildi mi?)",
            GetLastError());
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)exitCode;
}

// --------------------------------------------------------------------
// patch: Python apply_patches.py'yi cagir, IDA gerektirmiyor
// --------------------------------------------------------------------
static int CmdPatch(int argc, char** argv) {
    const char* src = (argc >= 3) ? argv[2] : NULL;
    const char* dst = (argc >= 4) ? argv[3] : NULL;

    char cmdline[2048];
    int n = wsprintfA(cmdline, "python \"%s\"", cfg::ApplyPatchesPy().c_str());
    if (src) n += wsprintfA(cmdline + n, " --src \"%s\"", src);
    if (dst) n += wsprintfA(cmdline + n, " --dst \"%s\"", dst);
    info("calistiriliyor: %s", cmdline);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        err("python basarisiz: %lu (Python 3 PATH'te mi?)", GetLastError());
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)exitCode;
}

// --------------------------------------------------------------------
// unpack: calisan Goley_'in unpacked PE memory'sini diske yazar (deneysel)
// --------------------------------------------------------------------
// Themida unpack process icinde calisir, sonunda original PE memory'de
// hazir olur. ImageBase'den IMAGE_DOS_HEADER okur, IMAGE_NT_HEADERS'i
// bulur, SizeOfImage kadar memory'yi okur, diske yazar.
//
// Bu kabaca dogru ama production-quality bir Scylla/ImpRec degil:
//   - Import table fix-up YOK
//   - Section header'lardaki SizeOfRawData duzeltmesi YOK
// Yine de hizli bir bakis icin yararli.
static int CmdUnpack(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool unpack <pid> [output.exe]"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[2], NULL, 0);
    const char* out = (argc >= 4) ? argv[3]
                                  : "C:\\Joygame\\Goley\\BinaryTr\\unpacked_Goley_.exe";

    WarnIfNotAdmin("PROCESS_VM_READ Goley_ uzerinde admin gerek");
    HANDLE hP = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                            FALSE, pid);
    if (!hP) { err("OpenProcess failed: %lu", GetLastError()); return 1; }

    HMODULE mods[16]; DWORD needed = 0;
    if (!EnumProcessModules(hP, mods, sizeof(mods), &needed)) {
        err("EnumProcessModules failed: %lu", GetLastError());
        CloseHandle(hP); return 1;
    }
    HMODULE main_mod = mods[0];  // ana modul her zaman ilk
    MODULEINFO mi = {};
    if (!GetModuleInformation(hP, main_mod, &mi, sizeof(mi))) {
        err("GetModuleInformation failed"); CloseHandle(hP); return 1;
    }
    info("Ana modul base=0x%p size=0x%lX", mi.lpBaseOfDll, mi.SizeOfImage);

    std::vector<BYTE> buf(mi.SizeOfImage);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hP, mi.lpBaseOfDll, buf.data(), buf.size(), &r)) {
        err("ReadProcessMemory failed: %lu (kismi okuma %lu byte)", GetLastError(), (unsigned long)r);
        CloseHandle(hP); return 1;
    }
    CloseHandle(hP);

    FILE* f = fopen(out, "wb");
    if (!f) { err("output yazilamadi: %s", out); return 1; }
    fwrite(buf.data(), 1, r, f);
    fclose(f);
    info("Yazildi: %s (%zu byte)", out, r);
    info("UYARI: Import table fix-up yapilmadi. Production icin Scylla onerilir.");
    return 0;
}

// --------------------------------------------------------------------
// dump-threads: her thread'in 32-bit CONTEXT snapshot'i
// --------------------------------------------------------------------
struct ModuleRange { char name[64]; ULONG_PTR base, size; };

static std::vector<ModuleRange> SnapshotModules(HANDLE hProc) {
    std::vector<ModuleRange> out;
    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_32BIT)) {
        if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
            err("EnumProcessModules failed: %lu", GetLastError());
            return out;
        }
    }
    DWORD n = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < n; i++) {
        MODULEINFO mi = {};
        if (!GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) continue;
        char name[MAX_PATH];
        if (!GetModuleBaseNameA(hProc, mods[i], name, sizeof(name))) continue;
        ModuleRange rr;
        lstrcpynA(rr.name, name, sizeof(rr.name));
        rr.base = (ULONG_PTR)mi.lpBaseOfDll;
        rr.size = (ULONG_PTR)mi.SizeOfImage;
        out.push_back(rr);
    }
    return out;
}

static std::string ClassifyEip(const std::vector<ModuleRange>& mods, ULONG_PTR eip) {
    for (const auto& m : mods) {
        if (eip >= m.base && eip < m.base + m.size) {
            char buf[128];
            wsprintfA(buf, "%s+0x%X", m.name, (UINT)(eip - m.base));
            return buf;
        }
    }
    char buf[32]; wsprintfA(buf, "?0x%X", (UINT)eip);
    return buf;
}

static int CmdDumpThreads(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool dump-threads <pid>"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[2], NULL, 0);
    if (!pid) { err("hatali pid"); return 1; }
    WarnIfNotAdmin("remote thread context okuma");

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { err("OpenProcess: %lu", GetLastError()); return 1; }

    auto mods = SnapshotModules(hProc);
    info("=== PID %lu thread dump (%zu modul) ===", pid, mods.size());

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        err("Toolhelp snapshot failed"); CloseHandle(hProc); return 1;
    }
    THREADENTRY32 te = { sizeof(te) };
    int total = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            total++;
            HANDLE hThr = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                     FALSE, te.th32ThreadID);
            if (!hThr) continue;
            SuspendThread(hThr);
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(hThr, &ctx)) {
                DWORD stack[16] = {0};
                SIZE_T got = 0;
                ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)ctx.Esp,
                                  stack, sizeof(stack), &got);
                printf("tid=%lu EIP=%s ESP=0x%08X\n",
                       te.th32ThreadID,
                       ClassifyEip(mods, ctx.Eip).c_str(),
                       ctx.Esp);
                // Sadece bilinen modullere isaret eden slot'lari yaz
                // (binlerce slot'tan gercek call-chain'i ayikla).
                int shown = 0;
                for (int i = 0; i < 16 && shown < 8; i++) {
                    std::string cls = ClassifyEip(mods, stack[i]);
                    if (cls[0] != '?') {
                        printf("    [esp+%-3d] 0x%08X  %s\n", i * 4, stack[i], cls.c_str());
                        shown++;
                    }
                }
            } else {
                printf("tid=%lu GetThreadContext failed: %lu\n",
                       te.th32ThreadID, GetLastError());
            }
            ResumeThread(hThr);
            CloseHandle(hThr);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    CloseHandle(hProc);
    info("=== %d thread ===", total);
    return 0;
}

// --------------------------------------------------------------------
// cleanup: acil temizlik
// --------------------------------------------------------------------
static int CmdCleanup(void) {
    WarnIfNotAdmin("admin process oldurme + HKLM silme");
    const char* targets[] = { "Goley_", "revival_wrapper", "unpacked_Goley_" };
    for (auto* prefix : targets) {
        auto pids = FindPidsByPrefix(prefix);
        for (DWORD pid : pids) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (h) {
                TerminateProcess(h, 1);
                CloseHandle(h);
                info("oldu %s PID %lu", prefix, pid);
            } else {
                err("%s PID %lu acilamadi (err=%lu)", prefix, pid, GetLastError());
            }
        }
    }
    CmdIfeoClear();
    return 0;
}

// --------------------------------------------------------------------
// dump-handles: target process'in tum kernel handle'larini Type+Name ile dok.
// --------------------------------------------------------------------
// NtQuerySystemInformation(SystemExtendedHandleInformation) tum sistemdeki
// handle'lari verir. PID filtreler, her birini DuplicateHandle ile kendi
// process'imize aktarir, NtQueryObject ile Type ve Name'i cikartiriz.
// "WaitForSingleObject(handle=0x5C, ...)" gibi bir takilma noktasinda
// 0x5C'nin gercek isimi bulmak icin kullaniyoruz.

#define SystemExtendedHandleInformation 0x40

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID        Object;
    ULONG_PTR    UniqueProcessId;
    ULONG_PTR    HandleValue;
    ULONG        GrantedAccess;
    USHORT       CreatorBackTraceIndex;
    USHORT       ObjectTypeIndex;
    ULONG        HandleAttributes;
    ULONG        Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR    NumberOfHandles;
    ULONG_PTR    Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } UNI_STR_local;
typedef struct { UNI_STR_local Name; } OBJ_NAME_INFO_local;
typedef struct { UNI_STR_local TypeName; ULONG TotalNumberOfObjects, TotalNumberOfHandles;
                 ULONG TotalPagedPoolUsage, TotalNonPagedPoolUsage; ULONG TotalNamePoolUsage;
                 ULONG TotalHandleTableUsage; ULONG HighWaterNumberOfObjects, HighWaterNumberOfHandles;
                 ULONG HighWaterPagedPoolUsage, HighWaterNonPagedPoolUsage; ULONG HighWaterNamePoolUsage;
                 ULONG HighWaterHandleTableUsage; ULONG InvalidAttributes; GENERIC_MAPPING GenericMapping;
                 ULONG ValidAccessMask; BOOLEAN SecurityRequired, MaintainHandleCount;
                 UCHAR TypeIndex, ReservedByte; ULONG PoolType, DefaultPagedPoolCharge, DefaultNonPagedPoolCharge;
               } OBJ_TYPE_INFO_local;

typedef LONG (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int CmdDumpHandles(int argc, char** argv) {
    if (argc < 3) { err("kullanim: revival_tool dump-handles <pid> [filter_handle_hex]"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[2], NULL, 0);
    if (!pid) { err("hatali pid"); return 1; }
    DWORD filter = (argc >= 4) ? (DWORD)strtoul(argv[3], NULL, 0) : 0;
    WarnIfNotAdmin("DuplicateHandle ve NtQueryObject genis erisim ister");

    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    auto pNtQuerySystemInfo = (NtQuerySystemInformation_t)GetProcAddress(hNt, "NtQuerySystemInformation");
    auto pNtQueryObject     = (NtQueryObject_t)GetProcAddress(hNt, "NtQueryObject");
    if (!pNtQuerySystemInfo || !pNtQueryObject) { err("ntdll resolution fail"); return 1; }

    // Boyutu dinamik olarak ayarla
    ULONG sz = 0x10000;
    BYTE* buf = (BYTE*)malloc(sz);
    LONG status;
    while (true) {
        ULONG ret = 0;
        status = pNtQuerySystemInfo(SystemExtendedHandleInformation, buf, sz, &ret);
        if (status == 0) break;
        if (status == (LONG)0xC0000004) {  // STATUS_INFO_LENGTH_MISMATCH
            sz *= 2;
            buf = (BYTE*)realloc(buf, sz);
            continue;
        }
        err("NtQuerySystemInformation failed: 0x%lX", status);
        free(buf);
        return 1;
    }

    auto hinfo = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    HANDLE hTarget = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                                  FALSE, pid);
    if (!hTarget) {
        err("OpenProcess(%lu) failed: %lu", pid, GetLastError());
        free(buf);
        return 1;
    }

    info("=== PID %lu handle dump (toplam %llu sistem genelinde) ===",
         pid, (ULONGLONG)hinfo->NumberOfHandles);
    int matched = 0;
    for (ULONG_PTR i = 0; i < hinfo->NumberOfHandles; i++) {
        auto& e = hinfo->Handles[i];
        if ((DWORD)e.UniqueProcessId != pid) continue;
        if (filter && (DWORD)e.HandleValue != filter) continue;
        matched++;

        HANDLE dup = NULL;
        if (!DuplicateHandle(hTarget, (HANDLE)e.HandleValue,
                             GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            printf("  h=0x%04X access=0x%X type_idx=%u  (DuplicateHandle err=%lu)\n",
                   (unsigned)e.HandleValue, e.GrantedAccess, e.ObjectTypeIndex,
                   GetLastError());
            continue;
        }
        BYTE tinfo[1024] = {0}; ULONG retLen = 0;
        char typeName[64] = "?", objName[256] = "<unnamed>";
        if (pNtQueryObject(dup, 2 /*ObjectTypeInformation*/, tinfo, sizeof(tinfo), &retLen) == 0) {
            auto* ti = (OBJ_TYPE_INFO_local*)tinfo;
            for (int j = 0; j < (int)(ti->TypeName.Length / sizeof(wchar_t)) && j < 63; j++) {
                wchar_t c = ti->TypeName.Buffer[j];
                typeName[j] = (c >= 0x20 && c < 0x80) ? (char)c : '?';
                typeName[j + 1] = 0;
            }
        }
        if (pNtQueryObject(dup, 1 /*ObjectNameInformation*/, tinfo, sizeof(tinfo), &retLen) == 0) {
            auto* ni = (OBJ_NAME_INFO_local*)tinfo;
            if (ni->Name.Length > 0 && ni->Name.Buffer) {
                int n = ni->Name.Length / sizeof(wchar_t);
                if (n > 255) n = 255;
                for (int j = 0; j < n; j++) {
                    wchar_t c = ni->Name.Buffer[j];
                    objName[j] = (c >= 0x20 && c < 0x80) ? (char)c : '?';
                }
                objName[n] = 0;
            }
        }
        CloseHandle(dup);
        printf("  h=0x%04X  type=%-12s  name='%s'\n",
               (unsigned)e.HandleValue, typeName, objName);
    }
    CloseHandle(hTarget);
    free(buf);
    info("=== %d handle %s ===", matched, filter ? "filter ile" : "PID'de");
    return 0;
}

// --------------------------------------------------------------------
// peek-stack <pid> <tid> [count]
// --------------------------------------------------------------------
// Belirli bir TID'in ESP'sinden count adet ham dword'u doker.
// dump-threads sadece modul-ici slot'lari ozetler; bu komut argument'lar
// gibi sayisal degerleri (handle, timeout, flag) gormek icin gerekli.
static int CmdPeekStack(int argc, char** argv) {
    if (argc < 4) { err("kullanim: revival_tool peek-stack <pid> <tid> [count=16]"); return 1; }
    DWORD pid = strtoul(argv[2], NULL, 0);
    DWORD tid = strtoul(argv[3], NULL, 0);
    int count = (argc >= 5) ? atoi(argv[4]) : 16;
    if (count < 1)  count = 16;
    if (count > 64) count = 64;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) { err("OpenThread(%lu) failed: %lu", tid, GetLastError()); return 1; }
    CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) {
        err("GetThreadContext: %lu", GetLastError());
        CloseHandle(hThread); return 1;
    }
    CloseHandle(hThread);

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { err("OpenProcess: %lu", GetLastError()); return 1; }

    info("tid=%lu  EIP=0x%08X  ESP=0x%08X  EBP=0x%08X",
         tid, ctx.Eip, ctx.Esp, ctx.Ebp);
    info("EAX=0x%08X  EBX=0x%08X  ECX=0x%08X  EDX=0x%08X",
         ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    info("ESI=0x%08X  EDI=0x%08X",
         ctx.Esi, ctx.Edi);
    DWORD slot = 0; SIZE_T got = 0;
    for (int i = 0; i < count; i++) {
        DWORD_PTR addr = (DWORD_PTR)ctx.Esp + (DWORD_PTR)i * 4;
        if (!ReadProcessMemory(hProc, (LPCVOID)addr, &slot, sizeof(slot), &got) || got != 4) {
            printf("  [esp+%-3d] (read failed)\n", i*4);
            break;
        }
        printf("  [esp+%-3d] 0x%08X  (%lu)\n", i*4, slot, (unsigned long)slot);
    }
    CloseHandle(hProc);
    return 0;
}

// --------------------------------------------------------------------
// walk-frames <pid> <tid> [max_depth]
// --------------------------------------------------------------------
// EBP frame chain'i takip et. Stack layout (gcc/msvc ABI):
//   [EBP+0]  = saved EBP   (onceki frame)
//   [EBP+4]  = return addr (caller'in instruction'i)
// Her frame'de modul classification yap (modul listesini al + RVA hesapla).
// Hot-spot: kontrol akisini geri tarayarak GERCEK caller chain'i cikar.
static int CmdWalkFrames(int argc, char** argv) {
    if (argc < 4) { err("kullanim: revival_tool walk-frames <pid> <tid> [max_depth=20]"); return 1; }
    DWORD pid = strtoul(argv[2], NULL, 0);
    DWORD tid = strtoul(argv[3], NULL, 0);
    int maxDepth = (argc >= 5) ? atoi(argv[4]) : 20;
    if (maxDepth < 1)  maxDepth = 20;
    if (maxDepth > 64) maxDepth = 64;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) { err("OpenThread: %lu", GetLastError()); return 1; }
    CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) { err("GetThreadContext: %lu", GetLastError()); CloseHandle(hThread); return 1; }
    CloseHandle(hThread);

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { err("OpenProcess: %lu", GetLastError()); return 1; }
    std::vector<ModuleRange> mods = SnapshotModules(hProc);

    info("tid=%lu  EIP=%s  ESP=0x%08X  EBP=0x%08X",
         tid, ClassifyEip(mods, ctx.Eip).c_str(), ctx.Esp, ctx.Ebp);

    DWORD ebp = ctx.Ebp;
    for (int depth = 0; depth < maxDepth; depth++) {
        if (ebp == 0 || ebp == 0xFFFFFFFF) { puts("  [frame chain end (ebp=0)]"); break; }
        DWORD savedEbp = 0, retAddr = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(DWORD_PTR)ebp, &savedEbp, sizeof(savedEbp), &got) || got != 4) {
            printf("  #%d ebp=0x%08X  (read failed at [ebp])\n", depth, ebp);
            break;
        }
        if (!ReadProcessMemory(hProc, (LPCVOID)(DWORD_PTR)(ebp + 4), &retAddr, sizeof(retAddr), &got) || got != 4) {
            printf("  #%d ebp=0x%08X  (read failed at [ebp+4])\n", depth, ebp);
            break;
        }
        printf("  #%-2d ebp=0x%08X  ret=%s\n",
               depth, ebp, ClassifyEip(mods, retAddr).c_str());
        if (savedEbp <= ebp || savedEbp - ebp > 0x100000) {
            puts("  [chain looks broken (savedEbp invalid)]");
            break;
        }
        ebp = savedEbp;
    }
    CloseHandle(hProc);
    return 0;
}

// --------------------------------------------------------------------
// read-mem <pid> <hex_addr> [count]
// --------------------------------------------------------------------
// PID'in adres uzayinda hex+ASCII dump. MCP bagimsiz disassemble-onu
// hazirlik (ham bytes'i baska arac ile cozeriz).
static int CmdReadMem(int argc, char** argv) {
    if (argc < 4) { err("kullanim: revival_tool read-mem <pid> <hex_addr> [count=64]"); return 1; }
    DWORD pid = strtoul(argv[2], NULL, 0);
    DWORD_PTR addr = (DWORD_PTR)strtoull(argv[3], NULL, 0);
    int count = (argc >= 5) ? atoi(argv[4]) : 64;
    if (count < 1)    count = 64;
    if (count > 4096) count = 4096;
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { err("OpenProcess: %lu", GetLastError()); return 1; }
    BYTE* buf = (BYTE*)malloc(count);
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, buf, count, &got)) {
        err("ReadProcessMemory: %lu", GetLastError());
        free(buf); CloseHandle(hProc); return 1;
    }
    for (SIZE_T i = 0; i < got; i += 16) {
        printf("%08X  ", (unsigned)(addr + i));
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < got) printf("%02X ", buf[i + j]);
            else             printf("   ");
        }
        printf(" |");
        for (SIZE_T j = 0; j < 16 && i + j < got; j++) {
            BYTE c = buf[i + j];
            putchar((c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
    free(buf); CloseHandle(hProc);
    return 0;
}

// --------------------------------------------------------------------
// help + dispatch
// --------------------------------------------------------------------
static int CmdHelp(void) {
    puts("revival_tool - revival icin tek CLI\n");
    puts("Kullanim: revival_tool <subcommand> [args]\n");
    puts("Subcommand'lar:");
    puts("  init <setup.exe>     Joygame setup'ini calistir, IFEO'yu ayarla, tool'u hazirla");
    puts("  launch               Goley_.exe baslat + patcher.dll inject + Resume");
    puts("  launch-unpacked      unpacked_Goley_PATCHED.exe'yi calistir (Themida yok)");
    puts("  launch-launcher      Goley.exe (launcher) baslat + patcher.dll inject (NMRunParam SetParam hook)");
    puts("  launch-args <args>   Goley_.exe baslat <args> ile (orn: \"TrAuth NoPopup\")");
    puts("  extract [vlh] [vld]  sifreli VLH/VLD oyun dosyalarini ac (argsiz = data klasoru)");
    puts("  patch <in> <out>     unpacked binary'e patches.json'u uygula (IDA gerek yok)");
    puts("  unpack <pid> [out]   calisan Goley_'in unpacked PE memory'sini diske yaz");
    puts("  inject <pid>         calisan PID'ye patcher.dll inject et");
    puts("  dump-threads <pid>   her thread'in EIP/return-addr'sini cikar");
    puts("  dump-handles <pid> [hex_handle]  PID'deki tum handle'lari Type+Name ile dok");
    puts("  peek-stack <pid> <tid> [count]  TID'in ESP'sinden ham dword'leri dok");
    puts("  read-mem <pid> <hex_addr> [count]  PID adres uzayindan hex+ASCII dump");
    puts("  walk-frames <pid> <tid> [depth]  EBP frame chain'i caller chain ile dok");
    puts("  ifeo set             revival_wrapper'i IFEO Debugger olarak ayarla");
    puts("  ifeo clear           IFEO Debugger kaydini kaldir");
    puts("  ifeo show            mevcut IFEO Debugger degerini yaz");
    puts("  cleanup              tum Goley_/wrapper oldur + IFEO temizle");
    puts("  ping                 sanity testi (ok yazar)");
    puts("  help                 bu yardim");
    puts("");
    puts("Cogu subcommand Yonetici (Administrator) gerektirir.");
    puts("");
    puts("Konfigurasyon:");
    puts("  GOLEY_INSTALL_DIR  environment var ile farkli kurulum klasoru kullanilabilir");
    puts("                     (varsayilan: C:\\Joygame\\Goley\\BinaryTr)");
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return CmdHelp();
    const char* cmd = argv[1];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help"))
        return CmdHelp();
    if (!strcmp(cmd, "ping"))             { puts("ok"); return 0; }
    if (!strcmp(cmd, "init"))             return CmdInit(argc, argv);
    if (!strcmp(cmd, "launch"))           return CmdLaunch();
    if (!strcmp(cmd, "launch-unpacked"))  return CmdLaunchUnpacked();
    if (!strcmp(cmd, "launch-launcher"))  return CmdLaunchLauncher();
    if (!strcmp(cmd, "launch-args"))      return CmdLaunchArgs(argc, argv);
    if (!strcmp(cmd, "patch"))            return CmdPatch(argc, argv);
    if (!strcmp(cmd, "extract"))          return CmdExtract(argc, argv);
    if (!strcmp(cmd, "unpack"))           return CmdUnpack(argc, argv);
    if (!strcmp(cmd, "inject"))           return CmdInject(argc, argv);
    if (!strcmp(cmd, "dump-threads"))     return CmdDumpThreads(argc, argv);
    if (!strcmp(cmd, "dump-handles"))     return CmdDumpHandles(argc, argv);
    if (!strcmp(cmd, "peek-stack"))       return CmdPeekStack(argc, argv);
    if (!strcmp(cmd, "read-mem"))         return CmdReadMem(argc, argv);
    if (!strcmp(cmd, "walk-frames"))      return CmdWalkFrames(argc, argv);
    if (!strcmp(cmd, "cleanup"))          return CmdCleanup();
    if (!strcmp(cmd, "ifeo")) {
        if (argc < 3) { err("kullanim: revival_tool ifeo set|clear|show"); return 1; }
        if (!strcmp(argv[2], "set"))   return CmdIfeoSet();
        if (!strcmp(argv[2], "clear")) return CmdIfeoClear();
        if (!strcmp(argv[2], "show"))  return CmdIfeoShow();
        err("bilinmeyen ifeo subcommand: %s", argv[2]);
        return 1;
    }

    err("bilinmeyen subcommand: %s", cmd);
    CmdHelp();
    return 1;
}
