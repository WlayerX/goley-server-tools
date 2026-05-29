# Themida Bypass — Implementasyon Detayları

## Yöntem özeti

Runtime DLL injection (`revival_patcher.dll`) ile Themida koruma katmanları aşılır. İki kritik teknik:

1. **Inline armor** — DllMain içinde, async thread beklemeden kill API stub'ları
2. **Hardware breakpoint** — Memory write yapmadan validation branch bypass

## Katman 1: Self-suicide engelleme

### Problem

Themida unpack sonrası integrity check yapar. Kurcalama tespit edilirse `TerminateProcess`, `ExitProcess` veya `NtTerminateProcess` ile process sonlandırılır. Unpack ResumeThread'den ~7 ms sonra başlar; async thread yaklaşımı bu süreye yetişemez.

### Çözüm: inline armor

DllMain içinde, ResumeThread öncesi:

```cpp
PatchStdcallStub(GetProcAddress(hKernel, "TerminateProcess"), 8);
PatchStdcallStub(GetProcAddress(hKernel, "ExitProcess"),      4);
PatchStdcallStub(GetProcAddress(hNt,     "NtTerminateProcess"), 8);
PatchStdcallStub(GetProcAddress(hNt,     "RtlExitUserProcess"), 4);
PatchStdcallStub(GetProcAddress(hNt,     "NtTerminateThread"), 8);

g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
```

Stub formatı: `mov eax, 1; ret N` (8 byte). API çağrıldığında başarı dönüş değeri alınır, gerçek işlem yapılmaz.

## Katman 2: DR sweep

### Problem

Themida `GetThreadContext` ile DR0..DR3 register'larını kontrol eder. Sıfır olmayan değer debugger tespiti tetikler.

### Çözüm

1. DR0'a validation branch adresi (0xD3DC4D) yazılır
2. EXCEPTION_SINGLE_STEP tetiklenir
3. VEH EIP'yi success path'e (0xD3DCF2) yazar
4. `ClearHardwareBreakpointAllThreads()` ile tüm thread'lerde DR0..DR3 sıfırlanır

## Katman 3: INT3 fingerprint

Themida ntdll wrapper'larına 0xCC (INT3) byte'ları serpiştirir. Debugger yokken exception process'i kapatır; yutulursa debugger tespiti.

VEH handler:

```c
if (code == EXCEPTION_BREAKPOINT &&
    eip >= ntdll_base && eip < ntdll_base + 0x200000) {
    exc->ContextRecord->Eip += 1;
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

## Katman 4: Validation branch

Themida unpack sonrası stack flag kontrolü yapar:

```
cmp byte ptr [esp+13h], 0
jne success_path
... fail path → SuicideHandler
```

Memory patch yapılamaz (tamper check). Çözüm: DR0 hardware breakpoint ile VEH'de stack flag değeri 1 olarak ayarlanır; cmp/jne instruction'ları gerçekten çalışır.

## Katman 5: Voluntary AV (açık)

Themida bilerek erişilemez adrese yazar. Naive swallow (EIP'ye dokunmadan continue) infinite loop oluşturur (50.000+ exception / 3 saniye).

Doğru çözüm: HDE32 ile instruction length hesaplanıp EIP ilerletilir. MinHook bundle'ında HDE32 mevcuttur; henüz implement edilmemiştir. Pratikte çoğu durumda tetiklenmez.

## Inline armor sırası

Yanlış sıra (başarısız):

```
DllMain → PatchThread (async) → DllMain return → ResumeThread → Themida kill (7 ms)
```

Doğru sıra (mevcut):

```
DllMain → inline stubs + VEH → PatchThread (async) → DllMain return → ResumeThread → Themida kill → stub'a düşer
```

## VEH exception matrisi

| Exception | EIP konumu | Davranış |
|-----------|------------|----------|
| EXCEPTION_SINGLE_STEP | 0xD3DC4D (validation) | EIP → 0xD3DCF2, DR temizle |
| EXCEPTION_BREAKPOINT | ntdll aralığı | EIP += 1 |
| EXCEPTION_ACCESS_VIOLATION | herhangi | Henüz doğru çözümde değil |

## Test prosedürü

```bat
src\tool\revival_tool.exe cleanup
src\tool\revival_tool.exe launch
:: patcher.log izle
```

Başarı kriterleri:
- Inline armor satırları ~8 ms içinde
- Process 30+ saniye yaşar
- MinHook hook'ları ACTIVE

## Teknik gereksinimler

| Konu | Gereksinim |
|------|------------|
| PE format | IAT/import resolution |
| x86 encoding | mov, ret instruction format |
| Windows API | kernel32/ntdll termination API listesi |
| Exception handling | VEH vs SEH farkı |
| Hardware BP | Per-thread DR register'ları |
| Loader lock | DllMain'de LoadLibrary çağrılmaz (deadlock) |
| Wow64 | Tüm araçlar x86 derlenmeli |

## İlgili belgeler

- [anti-cheat-overview.md](anti-cheat-overview.md)
- [../operations/runbook.md](../operations/runbook.md)
- [../project/status.md](../project/status.md)
