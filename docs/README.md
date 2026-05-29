# Dokümantasyon

goley-private-server teknik belgelerinin merkezi indeksi.

## Okuma sırası (yeni ekip üyeleri)

1. [architecture/overview.md](architecture/overview.md) — Sistem kapsamı ve bileşen ilişkileri
2. [project/status.md](project/status.md) — Mevcut implementasyon durumu ve bilinen kısıtlar
3. [operations/build.md](operations/build.md) — Derleme ortamı kurulumu
4. [operations/deployment.md](operations/deployment.md) — İlk kurulum ve çalıştırma
5. [operations/configuration.md](operations/configuration.md) — Ortam değişkenleri ve yol çözümlemesi

## Mimari

| Belge | İçerik |
|-------|--------|
| [architecture/overview.md](architecture/overview.md) | Üst düzey sistem görünümü |
| [architecture/client-stack.md](architecture/client-stack.md) | Tool, patcher, wrapper, extract bileşenleri |
| [architecture/server-stack.md](architecture/server-stack.md) | Backend servis topolojisi ve ProudNet katmanı |
| [architecture/data-flow.md](architecture/data-flow.md) | Client–server iletişim fazları |

## Operasyon

| Belge | İçerik |
|-------|--------|
| [operations/build.md](operations/build.md) | Client ve backend build prosedürleri |
| [operations/deployment.md](operations/deployment.md) | Kurulum, başlatma, hosts yapılandırması |
| [operations/configuration.md](operations/configuration.md) | Konfigürasyon parametreleri |
| [operations/runbook.md](operations/runbook.md) | Sorun giderme, log analizi, temizlik prosedürleri |

## Client runtime

| Belge | İçerik |
|-------|--------|
| [client/cli-reference.md](client/cli-reference.md) | `revival_tool.exe` komut referansı |
| [client/anti-cheat-overview.md](client/anti-cheat-overview.md) | Themida ve nProtect koruma katmanları |
| [client/themida-bypass.md](client/themida-bypass.md) | Runtime bypass implementasyon detayları |
| [client/binary-patches.md](client/binary-patches.md) | Statik binary patch kataloğu |
| [client/asset-extraction.md](client/asset-extraction.md) | VLH/VLD decryption pipeline |

## Backend services

| Belge | İçerik |
|-------|--------|
| [server/services.md](server/services.md) | Servis envanteri, portlar, başlatma |
| [server/protocol.md](server/protocol.md) | ProudNet protokol implementasyonu |

## Proje yönetimi

| Belge | İçerik |
|-------|--------|
| [project/status.md](project/status.md) | Implementasyon durumu matrisi |
| [project/roadmap.md](project/roadmap.md) | Açık iş kalemleri ve öncelikler |
| [project/glossary.md](project/glossary.md) | Terimler ve kısaltmalar |

## Hukuki

| Belge | İçerik |
|-------|--------|
| [legal/third-party-licenses.md](legal/third-party-licenses.md) | Bağımlı lisanslar (MinHook vb.) |

## Belge güncelleme kuralları

- Teknik değişiklik yapıldığında ilgili belge aynı PR/commit ile güncellenir.
- Durum matrisi (`project/status.md`) implementasyon ilerledikçe güncellenir.
- Binary patch eklendiğinde hem `client/binary-patches.md` hem `src/tool/patches.json` senkron tutulur.
- Protokol değişiklikleri `server/protocol.md` üzerinden takip edilir.

## Sürüm notu

Belgeler 2026-05-29 itibarıyla goley-private-server teslim paketi kapsamında gözden geçirilmiştir.
