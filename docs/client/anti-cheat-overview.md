# Anti-Cheat Katmanları — Genel Bakış

## Mimari

`Goley_.exe` iki bağımsız koruma katmanı ile gelir. Katmanlar üst üste bindiğinden her birinin ayrı ayrı ele alınması gerekir.

```
┌─────────────────────────────────────┐
│         Goley_.exe Process          │
├─────────────────────────────────────┤
│  Katman 1: Themida 2.x (packer)     │
│    Anti-tamper, anti-debug,         │
│    self-protection, voluntary AV    │
├─────────────────────────────────────┤
│  Katman 2: nProtect GameGuard (CC2)  │
│    Daemon handshake, error dialogs, │
│    init flag management             │
└─────────────────────────────────────┘
```

## Katman 1: Themida 2.x

Oreans tarafından ~2014 yılında yayınlanan packer + anti-debug + anti-tamper bütünü.

| Mekanizma | Davranış | Bypass durumu |
|-----------|----------|---------------|
| Anti-tamper | Unpack sonrası kod sayfalarını SHA hash'ler; değişiklik tespitinde process suicide | Memory patch yapılmaz |
| DR sweep | GetThreadContext ile DR0..DR3 kontrolü; sıfır olmayan değer → debugger tespiti | Bir kerelik DR0, hemen sweep |
| INT3 fingerprint | ntdll wrapper'larına 0xCC serpiştirme; yutulursa debugger tespiti | VEH içinde EIP+1 |
| Voluntary AV | Bilerek erişilemez adrese yazma; yutulursa debugger tespiti | TODO (HDE32 instruction-length advance) |
| ResumeThread yarışı | Unpack ResumeThread'den ~7 ms sonra başlar | Inline armor (DllMain'de) |

Detay: [themida-bypass.md](themida-bypass.md)

## Katman 2: INCA nProtect GameGuard (CC2)

~2010–2014 jenerasyonu Kore anti-cheat sistemi.

Dosya yapısı:

```
GameGuard/
    GameMon.des      — arka plan daemon
    npggNT.des       — NT kernel hook
    npsc.des         — sistem tarama
    ggscan.des       — bellek tarama
    ggerror.des      — hata dialog'ları
```

**Operasyonel durum:** Goley kurulum dizininde `GameGuard.disabled/` klasörü mevcuttur. nProtect dosyaları bulunamayınca hata moduna girer; bu durum statik patch ile yönetilir.

| Mekanizma | Bypass | Durum |
|-----------|--------|-------|
| Error MessageBox dialog'ları | P-1: error reporter no-op | Uygulandı |
| Init flag sıfırlama | P-2: event callback always-success | Uygulandı |
| GameMon handshake bekleme | WaitForSingleObject hook + SetEvent | TODO |

Detay: [binary-patches.md](binary-patches.md)

## Bypass özeti

```
KATMAN 1 (Themida)                    BYPASS YÖNTEMİ
─────────────────                     ──────────────
Anti-tamper                           Memory patch hiçbir zaman
DR sweep                              Bir kerelik DR0 → sweep
INT3 fingerprint                      VEH EIP+1
Voluntary AV                          TODO
ResumeThread yarışı                   Inline armor

KATMAN 2 (nProtect)                   BYPASS YÖNTEMİ
─────────────────                     ──────────────
Error dialogs                         P-1 statik patch
Event callback failure                P-2 statik patch
GameMon ready event                   TODO (WaitForSingleObject analizi)
```

## İlerleme durumu

Her iki katman bypass edildikten sonra splash ekranına ulaşılmıştır ("ChaguChagu V31927"). Init thread nProtect handshake event'inde beklemektedir.

Güncel durum: [../project/status.md](../project/status.md)

## İlgili belgeler

- [themida-bypass.md](themida-bypass.md)
- [binary-patches.md](binary-patches.md)
- [../architecture/overview.md](../architecture/overview.md)
