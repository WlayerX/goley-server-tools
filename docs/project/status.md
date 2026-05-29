# Proje Durumu

Son güncelleme: 2026-05-29

## Durum matrisi

### Client runtime

| Bileşen | Durum | Not |
|---------|-------|-----|
| Build sistemi | Tamamlandı | `build_all.bat`; dinamik yol çözümlemesi |
| revival_tool CLI | Tamamlandı | init, launch, extract, patch, unpack, inject, dump-threads, ifeo, cleanup |
| Yol A (runtime bypass) | Kısmi | Splash görünür; init thread bloke |
| Inline armor | Tamamlandı | DllMain race fix |
| Themida INT3 swallow | Tamamlandı | VEH EIP+1 |
| Themida validation HW BP | Tamamlandı | DR0 + sweep |
| nProtect MessageBox suppression | Tamamlandı | IAT hijack + HW BP |
| Yol B (statik patch) | Kısmi | 42 MB Working Set; pencere açılmaz |
| P-1, P-2 statik patch | Doğrulandı | 26 MB → 42 MB ilerleme |
| VLD/VLH decrypt | Tamamlandı | Türkçe çeviri tam |
| Themida voluntary AV | Açık | HDE32 implementasyonu bekliyor |

### Backend services

| Bileşen | Durum | Not |
|---------|-------|-----|
| ProudNet TCP handshake | Tamamlandı | Mock client doğrulandı |
| RMI dispatch | İskelet | Ana metodlar mevcut |
| Entry server | Stub | Her login başarılı |
| Lobby server | İskelet | Sabit oda listesi |
| Battle server | İskelet | UDP relay mevcut |
| Daum auth | İskelet | — |
| Patch server | Operasyonel | HashV2.VLL + PatchInfo.bin |
| Launcher web | Operasyonel | Cached HTML |
| Gerçek client entegrasyonu | Doğrulanmadı | Client splash sonrası ilerlemedi |

## Yol A — Bloke noktası

Inline armor + Themida bypass + nProtect MessageBox suppression sonrası:
- Splash ekranı görünür ("ChaguChagu V31927")
- Korece "초기화중" (Yükleniyor) yazısı sabit kalır
- Process 80+ saniye yaşar

**Kök neden:** Init thread, nProtect GameMon ready event'ini bekliyor. GameMon daemon runtime'da çalıştırılmadığı için event signal edilmiyor.

**Sonraki adım:** `WaitForSingleObject` hook ile beklenen handle'ı logla (NtQueryObject ile handle adı). Tespit sonrası `SetEvent` ile signal et.

## Yol B — Bloke noktası

P-1 + P-2 patch sonrası:
- Working Set 42 MB'a ulaşır
- Pencere açılmaz
- IAT sağlıklı (CreateWindowExW resolve edilmiş) ama API çağrılmıyor

**Sonraki adım:** Takılan PID'e `dump-threads` çek. EIP cluster analizi: büyük olasılıkla `WaitForMultipleObjects` aralığı (0x8E4A9C..0x8E5BEF).

## Bilinmeyenler

| Konu | Etki |
|------|------|
| Kritik WaitForSingleObject site'i (94 aday) | Yol A ilerlemesi |
| nProtect handshake event türü (kernel handle vs. memory-mapped) | Bypass yöntemi seçimi |
| Backend network handshake yeterliliği | Client bağlantı başarısı |
| ProudNet encryption algoritması | Gerçek client entegrasyonu |

## Son tamamlanan işler

- Inline armor mimari fix (Sleep tuning yerine yapısal çözüm)
- Themida INT3 swallow VEH implementasyonu
- Statik patch P-1 + P-2 doğrulaması
- P-3 attempt + revert (over-patch)
- Eski PowerShell helper'ların revival_tool CLI'ında birleştirilmesi
- Hardcoded yolların kaldırılması
- VLD çözücü + goley_real_code.bin depo entegrasyonu
- Backend services repo entegrasyonu

## İlgili belgeler

- [roadmap.md](roadmap.md)
- [../client/anti-cheat-overview.md](../client/anti-cheat-overview.md)
- [../server/services.md](../server/services.md)
