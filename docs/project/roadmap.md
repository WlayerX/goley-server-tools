# Yol Haritası

Öncelik sırasına göre açık iş kalemleri.

## P0 — Kritik (client ilerlemesi)

| ID | İş kalemi | Yol | Bağımlılık |
|----|-----------|-----|------------|
| C-01 | `WaitForSingleObject` hook ile handle adını logla | A | patcher.dll |
| C-02 | Tespit edilen handle'ı `SetEvent` ile signal et | A | C-01 |
| C-03 | `sub_8E70E0` içindeki `sub_D35720` çağrılarını cerrahi NOP | B | IDA analizi |
| C-04 | HDE32 instruction-length advance ile voluntary AV swallow | A/B | MinHook HDE32 |

## P1 — Backend tamamlama

| ID | İş kalemi | Bağımlılık |
|----|-----------|------------|
| S-01 | SQLite kullanıcı DB | — |
| S-02 | Lobby oda listesi kalıcılığı | S-01 |
| S-03 | Battle server maç state recording (replay) | — |
| S-04 | Daum auth tam emülasyonu (OAuth akışı) | — |
| S-05 | Patch server CDN cache mantığı (hash fingerprint uyumu) | — |
| S-06 | Gerçek client packet capture ve mock client karşılaştırması | Client ilerlemesi |

## P2 — İyileştirmeler

| ID | İş kalemi | Bağımlılık |
|----|-----------|------------|
| I-01 | Config dosyası (paths.ini) — environment variable yerine | — |
| I-02 | `revival_tool unpack` import table reconstruction (Scylla benzeri) | — |
| I-03 | Backend servisleri tek orchestrator altında birleştirme | — |
| I-04 | ProudNet encryption analizi ve implementasyonu | S-06 |
| I-05 | CI/CD pipeline (build + smoke test) | — |

## Tamamlanma kriterleri

### Client tam çalışır durum

- [ ] Splash sonrası init tamamlanır
- [ ] Launcher WebView backend'e bağlanır
- [ ] Patch server update kontrolü geçer
- [ ] Entry-server login handshake başarılı

### Backend production-ready

- [ ] Kullanıcı DB operasyonel
- [ ] Lobby oda yönetimi kalıcı
- [ ] Gerçek client ile end-to-end test geçer
- [ ] Packet format doğrulandı

## İlgili belgeler

- [status.md](status.md)
- [../architecture/overview.md](../architecture/overview.md)
