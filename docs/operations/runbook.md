# Operasyonel Runbook

## Log izleme

### patcher.log

Konum: depo kökü (`patcher.log`)

Canlı takip:

```bat
powershell -Command "Get-Content patcher.log -Wait -Tail 50"
```

Beklenen başarılı launch pattern'i (~10 ms içinde):

```
[hh:mm:ss.fff P=NNNN] DLL_PROCESS_ATTACH (VEH+HWBP+DialogKiller)
[...] Patched [inline] kernel32!TerminateProcess @ 0x...
[...] Patched [inline] kernel32!ExitProcess @ 0x...
[...] Patched [inline] ntdll!NtTerminateProcess @ 0x...
[...] [inline] VEH installed
[...] PatchThread starting (VEH+HWBP+MinHook refresh-loop mode)
[...] MinHook: CreateProcessA/W hooks ACTIVE
```

Anomali: yalnızca `ATTACH` ardından hemen `DETACH` → inline armor race kaybı. [../client/themida-bypass.md](../client/themida-bypass.md) inline armor sırası bölümüne bakın.

### wrapper.log

Konum: depo kökü (`wrapper.log`)

Wrapper process spawn, DLL injection ve child exit code bilgisi.

### Backend servis logları

Konum: `server/logs/` veya stdout (JSON-benzeri structured log).

Verbose mod:

```bat
set GOLEY_LOG_LEVEL=debug
.\bin\entry-server.exe
```

## Takılan process analizi

Splash ekranında "초기화중" (Yükleniyor) yazısında kalma:

```bat
tasklist | findstr /i goley_
src\tool\revival_tool.exe dump-threads <PID>
```

Çıktı yorumlama:

| EIP konumu | Anlam |
|------------|-------|
| `ntdll.dll+...` | Senkronizasyon objesi bekleniyor |
| `image+0x...` | Goley kodunda; IDA ile handle analizi |

## Temizlik prosedürü

Process kill edilemiyorsa veya wrapper kalmışsa:

```bat
src\tool\revival_tool.exe cleanup
```

Bu komut idempotent'tir:
- Tüm Goley_/wrapper PID'lerini sonlandırır
- IFEO kaydını siler

## Test prosedürü (her değişiklik sonrası)

```bat
src\tool\revival_tool.exe cleanup
src\tool\revival_tool.exe launch
:: patcher.log izle
```

Başarı kriterleri:
- Inline armor satırları ~8 ms içinde görünür
- Process 30+ saniye yaşar (Themida bypass başarılı)
- Splash ekranı görünür

## Working Set analizi (statik patch)

Statik patch sonrası init ilerlemesini ölçmek için Task Manager Working Set değerini izleyin:

| Working Set | Durum |
|-------------|-------|
| ~26 MB | Takılma (patch öncesi) |
| ~42 MB | P-1 + P-2 sonrası ilerleme |
| Gerileme | Over-patch (P-3 hatası örneği) |

## Backend sorun giderme

| Belirti | Kontrol |
|---------|---------|
| Client bağlanamıyor | `setup-hosts.ps1` çalıştırıldı mı? |
| Patch check fail | `Real_Server_Patch/` altında Goley.exe kopyalandı mı? |
| Port conflict | `netstat -an | findstr "2270 2271 2272 80 8080"` |
| Servis başlamıyor | `server/logs/` altında hata logları |

## DNS geri alma

Test sonrası hosts dosyasını eski haline getirmek için:

```bat
cd server
.\scripts\restore-hosts.ps1
```

## İlgili belgeler

- [deployment.md](deployment.md)
- [../project/status.md](../project/status.md)
- [../client/themida-bypass.md](../client/themida-bypass.md)
