# Backend Services — Operasyonel Referans

## Genel

Backend services, Goley istemcisinin bağlandığı orijinal sunucu altyapısının Go implementasyonudur. Her servis bağımsız binary olarak derlenir ve ayrı process olarak çalışır.

## Servis envanteri

| Servis | Binary | Port | Protokol | Sorumluluk |
|--------|--------|------|----------|------------|
| entry-server | `bin/entry-server.exe` | 2270/TCP | ProudNet | Login, karakter slot listesi |
| lobby-server | `bin/lobby-server.exe` | 2271/TCP | ProudNet | Oda listesi, oda kurma, lobby chat |
| battle-server | `bin/battle-server.exe` | 2272/TCP + UDP | ProudNet + relay | Maç kurma, P2P NAT hole punching |
| daum-auth | `bin/daum-auth.exe` | HTTP | HTTP | Daum hesap login emülasyonu |
| patch-server | `bin/patch-server.exe` | 80/HTTP | HTTP | Client update kontrolü |
| launcher-web | `bin/launcher-web.exe` | 8080/HTTP | HTTP | MSHTML launcher sayfası |
| login-server | `bin/login-server.exe` | 2270/TCP | ProudNet | Eski stub; geriye uyumluluk |

## Build

```bat
cd server
make build
```

Alternatif:

```bat
go build -o bin/ ./cmd/...
```

## Başlatma

### Tüm servisler

```bat
cd server
.\scripts\start-all.ps1
```

### Tek tek

```bat
.\bin\entry-server.exe
.\bin\lobby-server.exe
.\bin\battle-server.exe
.\bin\daum-auth.exe
.\bin\patch-server.exe
.\bin\launcher-web.exe
```

## DNS yapılandırması

Client orijinal Joygame DNS isimlerini çözer. Yerel ortamda hosts yönlendirmesi gerekir (yönetici):

```bat
.\scripts\setup-hosts.ps1
```

Eklenen kayıtlar:

```
127.0.0.1   cdn.joygamedl.com
127.0.0.1   joygame.com
127.0.0.1   www.joygame.com
```

Geri alma: `.\scripts\restore-hosts.ps1`

## Patch server binary gereksinimleri

`web/launcher/chagu/Real_Server_Patch/` altında stub dosyalar mevcuttur (`HashV2.VLL`, `PatchInfo.bin`). Client update kontrolü için orijinal binary'ler kurulum ortamından kopyalanmalıdır:

```bat
copy "C:\Joygame\Goley\Goley.exe" web\launcher\chagu\Real_Server_Patch\Goley.exe
copy "C:\Joygame\Goley\LauncherRestarter.exe" web\launcher\chagu\Real_Server_Patch\LauncherRestarter.exe
```

Bu dosyalar depo dışında tutulur (`.gitignore`).

## Servis akış modeli

```
Client ──TCP──► entry-server (login)
                    │ NotifyLoginOk + token
                    ▼
Client ──TCP──► lobby-server (oda listesi, chat)
                    │ GotoGameRoom + roomGuid
                    ▼
Client ──TCP+UDP──► battle-server (maç, P2P relay)
```

**Tasarım notu:** Maç mantığı client-side'dır. Backend yalnızca authentication, matchmaking ve P2P relay sağlar.

## Mevcut implementasyon seviyesi

| Bileşen | Durum |
|---------|-------|
| ProudNet TCP handshake | Implement; mock client ile doğrulandı |
| RMI dispatch | İskelet; ana metodlar mevcut |
| Entry server | Stub: her login başarılı |
| Lobby server | İskelet; sabit oda listesi |
| Battle server | İskelet; UDP relay mevcut |
| Daum auth | İskelet |
| Patch server | HashV2.VLL + PatchInfo.bin servis ediyor |
| Launcher web | Cached HTML servis ediyor |
| Gerçek client entegrasyonu | Doğrulanmadı |

## Loglama

Structured logging (`slog`), stdout'a JSON-benzeri format.

```bat
set GOLEY_LOG_LEVEL=debug
.\bin\entry-server.exe
```

## Kod organizasyonu

```
server/
├── cmd/                    Servis giriş noktaları
├── internal/
│   ├── proudnet/           TCP framing, RMI, UDP relay
│   └── common/             Logger, hexdump
├── scripts/                Orchestration
├── web/                    Launcher HTML, patch dosyaları
├── Makefile
└── go.mod
```

## İlgili belgeler

- [protocol.md](protocol.md)
- [../architecture/server-stack.md](../architecture/server-stack.md)
- [../operations/deployment.md](../operations/deployment.md)
- [../project/status.md](../project/status.md)

> Tam dokümantasyon: [../README.md](../README.md)
