# Ölümcül 0xC0000005 Crash'ini Yakalama — Özet

Tamamlandı. `feat/bypass-diagnostics` branch'inde, commit `18899d2`, author `hamitarsln`, Claude co-author yok.

## Önce: dürüst durum tespiti

Rapor "başarılı" diyordu ama **loglar aksini söylüyor** — `wrapper.log`'ta her run şununla bitiyor:

```text
ResumeThread returned 1
Child exited with code 3221225477   ← 0xC0000005 (ACCESS_VIOLATION)
```

Oyun menüye ulaşmıyor, `ResumeThread`'den ~0.8sn sonra çöküyor. Üstelik:

- `patcher_crash.log` sadece rescue ettiğimiz **2 exception**'ı içeriyor
  (ILL @ `0x017FD394` FORCED adv=2 → AV @ `0x017FD396` clean adv=1), ikisi de aynı
  garip register context'iyle (EAX=1, ESI=`0x017FBCBA`, EDI=`0x74D5300E` [kendi DLL'imiz],
  EBP=`0xEFC40014` [non-canonical]) → Themida VM-protected bytecode'unu brute-force
  single-step ediyoruz.
- `patcher.log` `54.110`'da **aniden bitiyor** (ne `HB` heartbeat, ne `InitWaitHooks`
  satırları), süreç `54.933`'te ölüyor.
- **Öldüren `0xC0000005` first-chance VEH'imize HİÇ düşmüyor** (cap 12, sadece 2 dump).
  Yani ölümcül darbeye **körüz**.

Bu yüzden kör kör kod değiştirmek yerine, senin seçtiğin gibi **önce o crash'i görünür kıldım** (diagnostics-first).

## Eklenen diagnostics (sadece enstrümantasyon — bypass davranışı DEĞİŞMEDİ)

**Commit `18899d2`** — `feat(diag): last-chance UEF + EIP bytes/TID in crash dump to capture the fatal exit`

| # | Ekleme | Amaç |
|---|--------|------|
| 1 | **Last-chance UEF** (`SetUnhandledExceptionFilter`) | First-chance VEH'i atlayıp ölmek üzere olan exception'ı tam ölüm anında dump'lar, sonra Themida'nın önceki top-level filter'ına zincirler (davranış korunur). `InstallLastChanceFilter` + `ReassertLastChanceFilter` (1Hz heartbeat'te yeniden kurar, Themida UEF'i ele geçirdiyse loglar). |
| 2 | **DumpCrashContext zenginleştirildi** | Başlığa `tid=`, faulting EIP'de **16-byte hexdump** (`bytes@EIP=...`) → hangi opcode stream'inde (Themida VM) takıldığımızı görmek için. |
| 3 | **`GOLEY_MBW_IAT_VA` benign filter'ı sessizlikten çıkarıldı** (capped) | Öldüren AV oraya sessizce gidiyorsa artık görünür. |

**Dosyalar:** `bypass/veh_handler.cpp` + `.h`, `main/patcher_main.cpp`.
Sadece `CONTEXT` okunuyor / UEF kuruluyor / log basılıyor — **`.text`'e dokunulmadı**, rescue kararları değişmedi.

## Doğrulama (sende, Windows'ta) — bu sefer ÜÇ olasılıktan birini arıyoruz

1. `src\patcher\build.bat` → derle
2. `start.bat` → çöküşü tekrarla
3. `patcher.log` + `patcher_crash.log` yapıştır

Loglarda hangisi çıkarsa bir sonraki adımı o belirler:

- **`CRASH [UNHANDLED-LASTCHANCE]` bloğu çıkarsa** → öldüren gerçek bir exception; EIP / `bytes@EIP` / stack'inden nereyi/neyi rescue edeceğimize (veya force single-step'in kök neden olup olmadığına) karar veririz.
- **`[veh] IAT-probe AV swallowed silently` çıkarsa** → benign filter öldüreni yutuyormuş, onu sıkılaştırırız.
- **Hiçbiri çıkmazsa** (last-chance dump yok + IAT log yok + `NtTerminateProcess`/`RtlExitUserProcess` hook log yok) → güçlü kanıt: Themida **direct-syscall ile `NtTerminateProcess(self, 0xC0000005)`** anti-tamper kill yapıyor (VEH'i, UEF'i ve ntdll-stub hook'umuzu baypaslıyor). O zaman sıradaki adım (ayrı commit) syscall-seviyesi yakalama olur.

## Not — clang sahte hataları

IDE'de bir sürü kırmızı clang hatası görünebilir (`winsock2.h file not found`, `WINAPI undefined`, `__try undeclared` vb.). Bunlar **sahte**: macOS clang'ında Windows SDK yok, `winsock2.h` bulunamayınca `WINAPI`/`__try`/`PEXCEPTION_POINTERS` tanımsız kalıp tüm dosya hatalı görünüyor. Kod MSVC/x86 için doğru; brace dengesi tuttu (veh_handler 61/61, patcher_main 95/95). Gerçek derleme sende.
