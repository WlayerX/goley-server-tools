# Veri Akışı

## Yol A — Runtime bypass (Themida'lı binary)

```
Kullanıcı
    │
    ▼
revival_tool launch
    │
    ├── IFEO Debugger kaydı set
    └── CreateProcessA(Goley_, CREATE_SUSPENDED)
            │
            ▼
OS IFEO → revival_wrapper.exe
    │
    ├── CreateProcessW(Goley_.exe, CREATE_SUSPENDED)
    ├── LoadLibrary → patcher.dll inject
    │       │
    │       └── DllMain:
    │             ├── Inline armor (kill API stubs)
    │             ├── VEH install
    │             └── PatchThread (async)
    └── ResumeThread
            │
            ▼
Goley_.exe ana thread
    │
    ├── Themida unpack
    ├── Validation BP → VEH EIP rewrite
    ├── INT3 → VEH EIP+1
    └── MinHook: child re-exec → DLL inject
            │
            ▼
Splash: "ChaguChagu V31927" + "초기화중"
    │
    └── nProtect GameMon ready event bekleniyor (bloke)
```

## Yol B — Statik patch (unpacked binary)

```
Kullanıcı
    │
    ▼
revival_tool patch <input> <output>
    │
    └── apply_patches.py
          ├── patches.json oku
          ├── PE section table → RVA/file offset
          └── Patched bytes yaz
                │
                ▼
revival_tool launch-unpacked
    │
    └── Patched binary başlat (Themida yok, nProtect patch'li)
            │
            ▼
Init pipeline (42 MB Working Set'e kadar ilerler, pencere açılmaz)
```

## Client–server tam akış

```
┌─────────┐     HTTP 8080      ┌──────────────┐
│ Client  │ ──────────────────►│ launcher-web │
└────┬────┘                    └──────────────┘
     │
     │  HTTP 80 (patch check)
     ▼
┌──────────────┐
│ patch-server │
└──────────────┘
     │
     │  TCP 2270 (ProudNet handshake + login)
     ▼
┌──────────────┐
│entry-server  │── NotifyLoginOk + token ──►
└──────────────┘
     │
     │  TCP 2271
     ▼
┌──────────────┐
│lobby-server  │── Oda listesi, chat, GotoGameRoom ──►
└──────────────┘
     │
     │  TCP 2272 + UDP
     ▼
┌──────────────┐
│battle-server │── Room setup, P2P relay ──►
└──────────────┘
     │
     │  Client-side P2P
     ▼
┌─────────┐ ◄──── UDP/TCP ────► ┌─────────┐
│Client A │                     │Client B │
└─────────┘                     └─────────┘
```

## DNS yönlendirme

Client orijinal Joygame DNS isimlerini çözmeye çalışır. Yerel geliştirme ortamında Windows hosts dosyası ile yönlendirme yapılır:

```
127.0.0.1   cdn.joygamedl.com
127.0.0.1   joygame.com
127.0.0.1   www.joygame.com
```

Script: `server/scripts/setup-hosts.ps1`

## Asset extraction akışı

```
Character.VLH ──MD5(master)──► index table ──16-byte key──► MD5 ──► Character.VLD decrypt
                                                                              │
                                                                              ▼
                                                                    zlib streams → files
                                                                              │
                                                                              ▼
                                                              extracted/character/*.X
```

## Log dosyaları

| Dosya | Kaynak | İçerik |
|-------|--------|--------|
| `patcher.log` | revival_patcher.dll | Bypass adımları, exception handling |
| `wrapper.log` | revival_wrapper.exe | Process spawn, injection |
| `server/logs/*.log` | Backend servisleri | ProudNet handshake, RMI dispatch |

## İlgili belgeler

- [overview.md](overview.md)
- [client-stack.md](client-stack.md)
- [server-stack.md](server-stack.md)
- [../operations/runbook.md](../operations/runbook.md)
