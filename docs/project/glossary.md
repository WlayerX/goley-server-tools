# Sözlük

## Proje terimleri

| Terim | Açıklama |
|-------|----------|
| goley-private-server | Bu projenin resmi adı; Goley istemcisi için özel sunucu platformu |
| Client runtime | `src/` altındaki tool, patcher, wrapper ve extract modülleri |
| Backend services | `server/` altındaki Go servisleri |
| Yol A | Runtime bypass: Themida'lı orijinal binary + DLL injection |
| Yol B | Statik patch: unpacked binary üzerine byte-level patch |
| Inline armor | DllMain içinde kill API stub'ları; self-suicide engelleme |
| IFEO | Image File Execution Options; Windows registry debugger hook |

## Anti-cheat terimleri

| Terim | Açıklama |
|-------|----------|
| Themida | Oreans packer + anti-debug + anti-tamper (2.x, ~2014) |
| nProtect GameGuard | INCA anti-cheat sistemi (CC2 jenerasyonu, ~2010–2014) |
| GameMon.des | nProtect arka plan daemon |
| VEH | Vectored Exception Handler |
| HW BP | Hardware Breakpoint (DR0..DR3 register'ları) |
| DR sweep | Themida'nın debug register kontrolü |
| Voluntary AV | Bilerek erişilemez adrese yazarak debugger tespiti |
| INT3 fingerprint | ntdll wrapper'larına serpiştirilmiş 0xCC byte'ları |

## Network terimleri

| Terim | Açıklama |
|-------|----------|
| ProudNet | Nettention network stack (Anipark tarafından kullanılmış) |
| RMI | Remote Method Invocation; ProudNet RPC mekanizması |
| PIDL | ProudNet Interface Definition Language serializer |
| NAT hole punching | P2P bağlantı için firewall traversal |
| UDP relay | P2P başarısız olduğunda paket yönlendirme |

## Dosya formatları

| Terim | Açıklama |
|-------|----------|
| VLH | Volante Header; şifreli index dosyası |
| VLD | Volante Data; şifreli asset container |
| HashV2.VLL | Patch server hash doğrulama dosyası |
| PatchInfo.bin | Client update metadata |

## Binary terimleri

| Terim | Açıklama |
|-------|----------|
| Goley_.exe | Ana oyun client binary'si (Themida pack'li) |
| BinaryTr.bin | Oyun engine modülü |
| unpacked_Goley_.exe | Themida unpack sonrası memory dump |
| Image base | PE varsayılan yükleme adresi (0x00400000) |
| RVA | Relative Virtual Address |
| Working Set | Process'in fiziksel bellek kullanımı (init ilerleme göstergesi) |

## Araç terimleri

| Terim | Açıklama |
|-------|----------|
| revival_tool.exe | Client runtime CLI |
| revival_patcher.dll | Runtime injection DLL |
| revival_wrapper.exe | IFEO debugger wrapper |
| MinHook | API hooking kütüphanesi (BSD 2-Clause) |
| Unicorn | CPU emulator (Python; asset decryption için) |
| goley_real_code.bin | Memory dump'tan elde edilen decrypt fonksiyon kodu |

## İlgili belgeler

- [../architecture/overview.md](../architecture/overview.md)
- [../client/anti-cheat-overview.md](../client/anti-cheat-overview.md)
