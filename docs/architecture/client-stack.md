# Client Runtime — Bileşen Mimarisi

## Genel bakış

Client runtime, `src/` altında dört modülden oluşur. Tüm bileşenler 32-bit (x86) olarak derlenir; hedef binary (`Goley_.exe`) 32-bit PE formatındadır.

## Bileşen envanteri

| Bileşen | Konum | Tür | Rol |
|---------|-------|-----|-----|
| `revival_tool.exe` | `src/tool/` | CLI | Tüm client iş akışlarının tek giriş noktası |
| `revival_patcher.dll` | `src/patcher/` | DLL | Runtime injection; Themida/nProtect bypass |
| `revival_wrapper.exe` | `src/wrapper/` | EXE | IFEO debugger wrapper; child process yönetimi |
| `decrypt.py` | `src/extract/` | Python | VLH/VLD asset decryption |
| `apply_patches.py` | `src/tool/` | Python | Statik binary patch uygulayıcı |
| `patches.json` | `src/tool/` | JSON | Patch kataloğu (makine okunabilir) |

## revival_tool.exe

32-bit konsol uygulaması. Komut tabanlı arayüz ile init, launch, extract, patch, unpack, inject, dump-threads, ifeo ve cleanup operasyonlarını yönetir.

**Yol çözümlemesi:** `GetModuleFileNameA` ile kendi konumunu tespit eder; iki seviye yukarı çıkarak depo kökünü belirler. Hardcoded path kullanılmaz.

**Goley kurulum yolu:** `GOLEY_INSTALL_DIR` ortam değişkeni (varsayılan: `C:\Joygame\Goley\BinaryTr`).

## revival_patcher.dll

`Goley_.exe` process'ine inject edilen DLL. Yaşam döngüsü:

```
DllMain (DLL_PROCESS_ATTACH)
  ├── Inline armor: kill API stub'ları (TerminateProcess, ExitProcess, NtTerminateProcess, ...)
  ├── VEH kurulumu
  └── PatchThread başlatma (async)

PatchThread (background)
  ├── MinHook init
  ├── CreateProcessA/W hook'ları
  └── Hardware breakpoint refresh loop
```

**Inline armor tasarım kararı:** Kill API stub'ları DllMain içinde, ResumeThread çağrılmadan önce kurulur. Themida unpack ResumeThread'den ~7 ms sonra self-suicide tetikleyebilir; async thread yaklaşımı bu yarış koşulunda başarısız olur.

Log çıktısı: `<repo_kökü>\patcher.log`

## revival_wrapper.exe

IFEO `Debugger` kaydı olarak `Goley_.exe` için yapılandırılır. Windows her `CreateProcess(Goley_)` çağrısını wrapper'a yönlendirir:

```
revival_wrapper.exe <Goley_.exe yolu> <orijinal argümanlar>
```

Wrapper akışı:

1. `CreateProcessW(Goley_.exe, CREATE_SUSPENDED)`
2. Remote `LoadLibraryW` ile patcher.dll inject
3. `ResumeThread`
4. Child exit code'unu propagate et

**Recursion guard:** `GLY_NO_WRAPPER` environment variable ile sonsuz IFEO döngüsü engellenir.

## decrypt.py

Anipark VLH/VLD şifreleme formatını çözer. Cipher'ın tam Python port'u yerine, memory dump'tan elde edilen `goley_real_code.bin` Unicorn x86 emulator'de çalıştırılır.

Anahtar türetme:

```
Master key = MD5("VolanteEncryptKey_84106141")
VLH decrypt → 16-byte ASCII key extract
VLD key    = MD5(ASCII key)
VLD decrypt → zlib streams → individual files
```

## apply_patches.py

IDA Pro gerektirmez. PE section table üzerinden RVA → file offset mapping yaparak `patches.json` içindeki byte değişikliklerini uygular.

## Bitness gerekçesi

| Bileşen | 32-bit zorunluluğu |
|---------|-------------------|
| patcher.dll | Hedef process ile aynı bitness |
| wrapper.exe | IFEO hedef binary ile aynı bitness |
| revival_tool.exe | `GetThreadContext` / `Wow64GetThreadContext` karmaşıklığından kaçınmak |

## Bağımlılıklar

| Bileşen | Harici bağımlılık |
|---------|-------------------|
| patcher.dll | MinHook (BSD 2-Clause, `src/patcher/minhook/`) |
| decrypt.py | Unicorn (`pip install unicorn`) |
| Tüm C/C++ bileşenleri | Visual Studio 2022 Build Tools, statik CRT (/MT) |

## İlgili belgeler

- [../client/cli-reference.md](../client/cli-reference.md)
- [../client/themida-bypass.md](../client/themida-bypass.md)
- [../client/binary-patches.md](../client/binary-patches.md)
- [../client/asset-extraction.md](../client/asset-extraction.md)
- [data-flow.md](data-flow.md)
