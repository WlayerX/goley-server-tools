# Sistem Mimarisi — Genel Bakış

## Amaç

goley-private-server, 2018'de resmi sunucuları kapanmış Goley istemcisinin özel ağ ortamında yeniden çalıştırılması için tasarlanmış entegre bir platformdur. Platform iki bağımsız ama birbirine bağımlı alt sistemden oluşur:

1. **Client Runtime** — Orijinal istemci binary'sinin Windows ortamında çalıştırılması
2. **Backend Services** — Orijinal sunucu altyapısının Go ile yeniden implementasyonu

## Problem alanı

Orijinal istemci (`Goley_.exe`) üç katmanlı bir engelle karşılaşır:

| Katman | Teknoloji | Etki |
|--------|-----------|------|
| Paketleme | Themida 2.x (Oreans, ~2014) | Runtime anti-debug, anti-tamper, self-protection |
| Anti-cheat | INCA nProtect GameGuard (CC2) | Daemon handshake, bellek tarama, process termination |
| Ağ | ProudNet (Nettention) | Kapatılmış resmi sunuculara bağlantı girişimi |

Client runtime bu koruma katmanlarını yönetir; backend services ağ protokolünü emüle eder.

## Üst düzey bileşen diyagramı

```
┌─────────────────────────────────────────────────────────────────┐
│                        goley-private-server                      │
├─────────────────────────────┬───────────────────────────────────┤
│       Client Runtime        │         Backend Services           │
│           (src/)            │            (server/)               │
├─────────────────────────────┼───────────────────────────────────┤
│  revival_tool.exe           │  entry-server      (TCP 2270)     │
│  revival_patcher.dll        │  lobby-server      (TCP 2271)     │
│  revival_wrapper.exe        │  battle-server     (TCP 2272+UDP)  │
│  decrypt.py                 │  daum-auth         (HTTP)          │
│                             │  patch-server      (HTTP 80)       │
│                             │  launcher-web      (HTTP 8080)     │
└─────────────────────────────┴───────────────────────────────────┘
              │                                    │
              └────────── ProudNet TCP/UDP ────────┘
```

## İki bypass stratejisi

Anti-cheat katmanları iki farklı yöntemle aşılabilir. Ekip, operasyonel gereksinimlere göre birini seçer:

| | Yol A: Runtime bypass | Yol B: Statik patch |
|---|---|---|
| Hedef binary | `Goley_.exe` (Themida'lı) | `unpacked_Goley_.exe` |
| Komut | `revival_tool launch` | `revival_tool patch` + `launch-unpacked` |
| DLL injection | Gerekli | Gereksiz |
| IFEO wrapper | Gerekli | Gereksiz |
| Avantaj | Orijinal layout korunur; runtime müdahale imkânı | Themida yarış koşulu yok; standalone exe |
| Dezavantaj | Self-protection karşı sert yarış koşulu | Önce unpack gerekir; patch kapsamı sınırlı |

Güncel ilerleme durumu: [../project/status.md](../project/status.md)

## Client–server iletişim fazları

```
Phase 1: Launcher
  MSHTML WebView  → launcher-web (HTTP 8080)
  WinINet GET     → patch-server (HTTP 80)

Phase 2: Authentication
  TCP connect     → entry-server (2270)
  RequestLogin    → NotifyLoginOk + token

Phase 3: Lobby
  TCP connect     → lobby-server (2271)
  Oda listesi, chat, GotoGameRoom

Phase 4: Match
  TCP + UDP       → battle-server (2272)
  Client-side P2P sync (server relay)
```

**Kritik tasarım kararı:** Goley'in maç mantığı client-side'dır. Backend yalnızca authentication, matchmaking ve P2P relay sağlar; oyun fiziği veya kural implementasyonu backend kapsamında değildir.

## Kapsam dışı

| Konu | Gerekçe |
|------|---------|
| Themida otomatik unpacker | Runtime bypass tercih edilmiştir; offline unpack için Scylla/ImpRec kullanılabilir |
| Resmi ProudNet kaynak kodu | Nettention mülkiyetindedir; yalnızca gözlemlenen davranış re-implement edilmiştir |
| Orijinal oyun binary'leri | Telif kapsamında; depo dışında tutulur |
| Maç fiziği / oyun kuralları | Client-side P2P sync ile yönetilir |

## İlgili belgeler

- [client-stack.md](client-stack.md) — Client runtime bileşen detayları
- [server-stack.md](server-stack.md) — Backend servis detayları
- [data-flow.md](data-flow.md) — Veri akış diyagramları
- [../client/anti-cheat-overview.md](../client/anti-cheat-overview.md) — Koruma katmanları analizi
