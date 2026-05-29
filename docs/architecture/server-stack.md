# Backend Services — Bileşen Mimarisi

## Genel bakış

Backend services, Goley istemcisinin bağlandığı orijinal sunucu altyapısının Go ile yeniden implementasyonudur. Anipark ProudNet (Nettention) network stack'inin gözlemlenen protokol davranışı modellenmiştir; resmi ProudNet kaynak kodu kullanılmaz.

## Servis topolojisi

```
                    ┌──────────────┐
                    │   Client     │
                    └──────┬───────┘
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │ launcher-web│ │ patch-server│ │  daum-auth  │
    │  HTTP 8080  │ │  HTTP 80    │ │    HTTP     │
    └─────────────┘ └─────────────┘ └─────────────┘
           │
    ┌──────▼──────┐ ┌─────────────┐ ┌─────────────┐
    │entry-server │ │lobby-server │ │battle-server│
    │  TCP 2270   │ │  TCP 2271   │ │ TCP 2272    │
    └─────────────┘ └─────────────┘ │ + UDP relay │
                                    └─────────────┘
```

## Servis envanteri

| Servis | Binary | Port | Protokol | Sorumluluk |
|--------|--------|------|----------|------------|
| entry-server | `cmd/entry-server/` | 2270/TCP | ProudNet | Login, karakter slot listesi |
| lobby-server | `cmd/lobby-server/` | 2271/TCP | ProudNet | Oda listesi, oda kurma, lobby chat |
| battle-server | `cmd/battle-server/` | 2272/TCP + UDP | ProudNet + UDP relay | Maç kurma, P2P NAT hole punching |
| daum-auth | `cmd/daum-auth/` | HTTP | HTTP | Daum hesap login emülasyonu |
| patch-server | `cmd/patch-server/` | 80/HTTP | HTTP | Client update kontrolü (PatchInfo.bin, HashV2.VLL) |
| launcher-web | `cmd/launcher-web/` | 8080/HTTP | HTTP | MSHTML WebView launcher sayfası |
| login-server | `cmd/login-server/` | 2270/TCP | ProudNet | Eski stub; geriye uyumluluk |

Her servis bağımsız Go binary olarak derlenir ve ayrı process olarak çalışır.

## ProudNet implementasyon katmanı

Ortak network kodu `server/internal/proudnet/` altında:

| Modül | Dosya | Sorumluluk |
|-------|-------|------------|
| Framing | `framing.go` | TCP framing (length-prefix + RMI ID), handshake (magic bytes + version + IV) |
| Serialization | `message.go` | PIDL serializer/deserializer (string, int32, GUID, bytes) |
| Routing | `rmi_ids.go` | RMI method ID registry |
| Server core | `server.go` | TCP listener, per-connection goroutine, handler registry |
| UDP relay | `udp_relay.go` | P2P NAT hole punching relay |

Handler kaydı: `s.Handle(RMI_ID, fn)`

## Servis akış modeli

CasualGame2 (Nettention sample) pattern'i izlenir:

```
Client ──TCP──► entry-server
                    │ NotifyLoginOk + token
                    ▼
Client ──TCP──► lobby-server
                    │ GotoGameRoom + roomGuid
                    ▼
Client ──TCP+UDP──► battle-server
                    │ P2P sync (server relay fallback)
```

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
| Gerçek client entegrasyonu | Doğrulanmadı (client splash sonrası ilerlemedi) |

## Ortak yardımcılar

`server/internal/common/`:

- `logger.go` — Structured logging (`slog`)
- `hexdump.go` — Packet debug çıktısı

Log seviyesi: `GOLEY_LOG_LEVEL=debug`

## Web asset'leri

| Konum | İçerik |
|-------|--------|
| `server/web/launcher/` | Launcher HTML (cached Joygame sayfası) |
| `server/web/launcher/chagu/Real_Server_Patch/` | Patch server stub dosyaları (HashV2.VLL, PatchInfo.bin) |

Orijinal Joygame binary'leri (`Goley.exe`, `LauncherRestarter.exe`) depo dışında tutulur; kurulum ortamından kopyalanması gerekir.

## İlgili belgeler

- [../server/services.md](../server/services.md) — Operasyonel başlatma prosedürleri
- [../server/protocol.md](../server/protocol.md) — Protokol detayları
- [data-flow.md](data-flow.md)
