# ProudNet Protokol Implementasyonu

## Genel

Backend services, Anipark ProudNet (Nettention) network stack'inin gözlemlenen protokol davranışını Go'da re-implement eder. Resmi ProudNet kaynak kodu kullanılmaz.

Referans kaynaklar:
- Nettention public sample uygulamaları (`Sample`, `Simple`, `CasualGame2`)
- Goley client runtime trafik gözlemleri

## Implementasyon katmanı

Konum: `server/internal/proudnet/`

### framing.go — TCP framing

- Length-prefix + RMI ID
- Client bağlantı handshake: magic bytes + version + magic IV
- Handshake tamamlandıktan sonra RMI layer'a geçiş

### message.go — PIDL serialization

Primitive tipler: string, int32, GUID, bytes

### rmi_ids.go — RMI method registry

CasualGame2 sample'ından miras alınan ID'ler + Goley-specific RPC'ler:

| RMI | Yön | Açıklama |
|-----|-----|----------|
| RequestLogin | Client → Server | Login isteği |
| NotifyLoginOk | Server → Client | Login başarı + token |
| GotoLobby | Server → Client | Lobby'ye yönlendirme |
| GotoGameRoom | Server → Client | Maç odasına yönlendirme |

### server.go — TCP server core

- TCP listener
- Per-connection goroutine
- Handler registry: `s.Handle(RMI_ID, fn)`

### udp_relay.go — UDP relay

P2P NAT hole punching için paket yönlendirme. Client'lar doğrudan UDP ile iletişim kuramazsa backend relay devreye girer.

## Bağlantı akışı

```
Client                          Backend
  │                                │
  │──── TCP connect (2270) ───────►│ entry-server
  │◄─── handshake (magic+ver+IV) ──│
  │──── RequestLogin ─────────────►│
  │◄─── NotifyLoginOk + token ────│
  │                                │
  │──── TCP connect (2271) ───────►│ lobby-server
  │◄─── handshake ─────────────────│
  │──── (token auth) ─────────────►│
  │◄─── oda listesi ───────────────│
  │◄─── GotoGameRoom + roomGuid ──│
  │                                │
  │──── TCP connect (2272) ───────►│ battle-server
  │──── UDP (NAT relay) ──────────►│
  │◄─── room setup ────────────────│
  │                                │
  │◄════ Client P2P sync ════════►│ (server relay fallback)
```

## Endpoint referansı

| Servis | Port | Transport |
|--------|------|-----------|
| entry-server | 2270 | TCP |
| lobby-server | 2271 | TCP |
| battle-server | 2272 | TCP + UDP |
| patch-server | 80 | HTTP |
| launcher-web | 8080 | HTTP |

Orijinal production endpoint'leri (referans):

| Servis | Adres |
|--------|-------|
| Login | 213.74.179.12:2270 |
| Game/Lobby | 213.74.179.12:20260 |

## Doğrulama durumu

| Konu | Durum |
|------|-------|
| TCP handshake format | Mock client ile doğrulandı |
| RMI dispatch iskelet | Implement |
| Login request/response yapısı | Stub (her login başarılı) |
| Encryption | Henüz analiz edilmedi |
| Gerçek client packet capture | Client splash sonrası ilerlemediği için yapılamadı |

## Packet analizi yöntemi

Gerçek client bağlandığında:

1. Backend servis logları her byte'ı kaydeder
2. Birden fazla session karşılaştırılarak header pattern tespit edilir
3. Mock client testleri ile farklar belirlenir

Olası packet header yapısı (henüz doğrulanmadı):

```
[2 veya 4 byte: packet length]
[2 byte: opcode / packet ID]
[1 byte: encryption flag (opsiyonel)]
[payload]
```

## Açık analiz konuları

- Packet header layout (length size, opcode size, byte order)
- Login request yapısı (username, password, client version)
- Session token format
- Handshake / key exchange
- Encryption algoritması (RC4-like stream cipher olası)
- Heartbeat / keepalive paketleri

## İlgili belgeler

- [services.md](services.md)
- [../architecture/server-stack.md](../architecture/server-stack.md)
- [../architecture/data-flow.md](../architecture/data-flow.md)
