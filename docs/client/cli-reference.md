# CLI Referansı — revival_tool.exe

## Genel

`revival_tool.exe`, client runtime operasyonlarının tek giriş noktasıdır. Yönetici yetkisi ile çalıştırılmalıdır.

Gerekçe:
- `Goley_.exe` manifesti `requireAdministrator`
- IFEO registry kaydı HKLM altında
- Remote process DLL injection için `PROCESS_ALL_ACCESS`

## Komut envanteri

| Komut | Açıklama |
|-------|----------|
| `init <setup.exe>` | Setup çalıştır, kurulum doğrula, IFEO ayarla |
| `launch` | Goley_.exe başlat + patcher.dll inject |
| `launch-unpacked` | Patched unpacked binary başlat |
| `extract [vlh vld]` | Şifreli oyun dosyalarını aç |
| `patch <in> <out>` | Unpacked binary'e patches.json uygula |
| `unpack <pid>` | Çalışan process'in memory dump'ını al |
| `inject <pid>` | Çalışan PID'ye patcher.dll inject et |
| `dump-threads <pid>` | Thread EIP/return-address zinciri |
| `ifeo set` | IFEO Debugger kaydı oluştur |
| `ifeo clear` | IFEO kaydını kaldır |
| `ifeo show` | Mevcut IFEO durumunu göster |
| `cleanup` | Goley_/wrapper process'lerini sonlandır + IFEO temizle |
| `ping` | Build/runtime sanity check |
| `help` | Komut listesi |

## init

Bir kerelik kurulum prosedürü.

```bat
src\tool\revival_tool.exe init "C:\path\to\GoleySetup.exe"
```

Akış:
1. Setup GUI başlatılır
2. Kurulum tamamlandıktan sonra `Goley_.exe` varlığı doğrulanır
3. IFEO Debugger kaydı ayarlanır

## launch

Standart client başlatma (Yol A — runtime bypass).

```bat
src\tool\revival_tool.exe launch
```

## launch-unpacked

Statik patch uygulanmış binary başlatma (Yol B).

```bat
src\tool\revival_tool.exe launch-unpacked
```

Ön koşul: `patch` komutu ile patched binary oluşturulmuş olmalı.

## extract

VLH/VLD asset decryption.

```bat
:: Tüm Data klasörü
src\tool\revival_tool.exe extract

:: Tek çift
src\tool\revival_tool.exe extract "C:\Joygame\Goley\Data\Character.VLH" "C:\Joygame\Goley\Data\Character.VLD"
```

Ön koşul: `pip install -r src\extract\requirements.txt`

Çıktı: `extracted/` altında kategorize edilmiş dosyalar.

## patch

Statik binary patch uygulama.

```bat
src\tool\revival_tool.exe patch ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_.exe" ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_PATCHED.exe"
```

Arka planda `apply_patches.py` çalışır; IDA Pro gerekmez.

## dump-threads

Takılan process analizi.

```bat
tasklist | findstr /i goley_
src\tool\revival_tool.exe dump-threads <PID>
```

Örnek çıktı:

```
tid=23456 EIP=ntdll.dll+0x6E4B0 ESP=0x002FFAE0 | image+0x935AB9 | image+0x8E70E0 | ...
```

## ifeo

IFEO Debugger registry yönetimi.

```bat
src\tool\revival_tool.exe ifeo show
src\tool\revival_tool.exe ifeo set
src\tool\revival_tool.exe ifeo clear
```

IFEO gerekçesi: nProtect "trusted re-launch" pattern'i ile Goley_.exe'yi child olarak spawn eder. IFEO kaydı olmadan child process'e DLL inject edilemez.

## cleanup

Idempotent temizlik.

```bat
src\tool\revival_tool.exe cleanup
```

## İlgili belgeler

- [../operations/deployment.md](../operations/deployment.md)
- [../operations/runbook.md](../operations/runbook.md)
- [binary-patches.md](binary-patches.md)
- [asset-extraction.md](asset-extraction.md)
