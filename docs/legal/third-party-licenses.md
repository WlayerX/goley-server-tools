# Üçüncü Taraf Lisansları

## MIT License

goley-private-server projesi MIT lisansı altında dağıtılır. Tam metin: [LICENSE](../../LICENSE)

## MinHook — BSD 2-Clause License

| Alan | Değer |
|------|-------|
| Konum | `src/patcher/minhook/` |
| Lisans | BSD 2-Clause |
| Tam metin | `src/patcher/minhook/LICENSE.txt` |
| Kullanım | API hooking (CreateProcessA/W) |

MinHook kaynak kodu ve lisans metni depo içinde korunmuştur.

## Unicorn Engine

| Alan | Değer |
|------|-------|
| Kullanım | `src/extract/decrypt.py` — x86 CPU emulation |
| Lisans | GPLv2 (runtime bağımlılık; kaynak kod depo içinde değil) |
| Kurulum | `pip install unicorn` |

Unicorn Python paketi olarak kullanılır; kaynak kodu depo içinde bundle edilmemiştir.

## Go standard library

Backend services Go standard library kullanır. Go lisansı: BSD-style (https://go.dev/LICENSE)

## Dış bağımlılık özeti

| Bileşen | Lisans | Depo içi | Runtime bağımlılık |
|---------|--------|----------|-------------------|
| MinHook | BSD 2-Clause | Evet | Evet (patcher.dll) |
| Unicorn | GPLv2 | Hayır | Evet (decrypt.py) |
| Go stdlib | BSD-style | Hayır | Evet (backend) |
| Visual Studio CRT | Microsoft | Hayır | Hayır (/MT statik link) |

## Telif notu

Orijinal Goley oyun binary'leri, asset dosyaları ve resmi sunucu kodu bu depoda yer almaz. Bunlar orijinal yayıncının (Joygame / Anipark) mülkiyetindedir.

ProudNet protokol implementasyonu, gözlemlenen davranışın re-implementation'ıdır; resmi Nettention kaynak kodu kullanılmamıştır.

Launcher HTML (`server/web/launcher/index.html`) Joygame launcher'ının cache'lenmiş versiyonudur.
