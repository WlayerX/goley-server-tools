# Deployment

## Ön koşullar

| Koşul | Doğrulama |
|-------|-----------|
| Client runtime build tamamlandı | `src\tool\revival_tool.exe ping` → `ok` |
| Backend build tamamlandı | `server\bin\entry-server.exe` mevcut |
| Goley installer mevcut | Joygame setup.exe erişilebilir |
| Yönetici yetkisi | cmd/Terminal "Yönetici olarak çalıştır" |

## İlk kurulum (client)

### 1. Build

```bat
build_all.bat
```

### 2. Goley kurulumu ve IFEO yapılandırması

```bat
src\tool\revival_tool.exe init "C:\path\to\GoleySetup.exe"
```

Tool akışı:
1. Setup GUI başlatır; kullanıcı kurulumu tamamlar
2. `Goley_.exe` varlığını doğrular (varsayılan: `C:\Joygame\Goley\BinaryTr\`)
3. IFEO Debugger kaydını ayarlar (HKLM)

Alternatif kurulum yolu:

```bat
set GOLEY_INSTALL_DIR=D:\Games\Goley\BinaryTr
src\tool\revival_tool.exe init "C:\path\to\GoleySetup.exe"
```

### 3. Client başlatma

```bat
src\tool\revival_tool.exe launch
```

## İlk kurulum (backend)

### 1. Build

```bat
cd server
make build
```

### 2. Patch server binary'leri

Client update kontrolü için orijinal binary'ler patch server dizinine kopyalanmalıdır:

```bat
copy "C:\Joygame\Goley\Goley.exe" server\web\launcher\chagu\Real_Server_Patch\Goley.exe
copy "C:\Joygame\Goley\LauncherRestarter.exe" server\web\launcher\chagu\Real_Server_Patch\LauncherRestarter.exe
```

Bu dosyalar `.gitignore` kapsamındadır; depo dışında tutulur.

### 3. Servisleri başlatma

```bat
cd server
.\scripts\start-all.ps1
```

### 4. DNS yönlendirme (bir kerelik)

Yönetici olarak:

```bat
.\scripts\setup-hosts.ps1
```

Geri alma:

```bat
.\scripts\restore-hosts.ps1
```

Eklenen kayıtlar:

```
127.0.0.1   cdn.joygamedl.com
127.0.0.1   joygame.com
127.0.0.1   www.joygame.com
```

## Servis portları

| Servis | Port | Protokol |
|--------|------|----------|
| entry-server | 2270 | TCP |
| lobby-server | 2271 | TCP |
| battle-server | 2272 | TCP + UDP |
| patch-server | 80 | HTTP |
| launcher-web | 8080 | HTTP |
| daum-auth | — | HTTP (dinamik) |

Tüm servislerin dinlediğini doğrulamak için `start-all.ps1` çıktısını kontrol edin.

## Statik patch yolu (alternatif deployment)

Themida'sız unpacked binary mevcutsa:

```bat
src\tool\revival_tool.exe patch ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_.exe" ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_PATCHED.exe"

src\tool\revival_tool.exe launch-unpacked
```

Bu yöntemde DLL injection ve IFEO gerekmez; yönetici yetkisi hâlâ gerekebilir (manifest `requireAdministrator`).

## Yeni clone sonrası smoke test

```bat
build_all.bat
src\tool\revival_tool.exe ping
src\tool\revival_tool.exe help
src\tool\revival_tool.exe ifeo show
src\tool\revival_tool.exe cleanup
```

Dört komut da hatasız tamamlanırsa build ortamı doğrulanmış demektir.

## İlgili belgeler

- [build.md](build.md)
- [configuration.md](configuration.md)
- [runbook.md](runbook.md)
- [../server/services.md](../server/services.md)
