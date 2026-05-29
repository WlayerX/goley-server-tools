# Build Prosedürleri

## Gereksinimler

### Client runtime

| Gereksinim | Sürüm / Not |
|------------|-------------|
| İşletim sistemi | Windows 10 veya 11 |
| Derleyici | Visual Studio 2022 Build Tools |
| Gerekli component | MSVC v143 — VS 2022 C++ x86/x64 build tools |
| Varsayılan vcvars yolu | `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat` |

Farklı kurulum yolu kullanılıyorsa `src/*/build.bat` içindeki `VS_PATH` satırı güncellenmelidir.

### Asset extraction

| Gereksinim | Sürüm / Not |
|------------|-------------|
| Python | 3.10+ |
| Unicorn | `pip install -r src\extract\requirements.txt` |

### Backend services

| Gereksinim | Sürüm / Not |
|------------|-------------|
| Go | 1.22+ |

## Client runtime build

Depo kökünden:

```bat
build_all.bat
```

Sıralı subbuild:

```
[1/3] revival_tool.exe    → src/tool/
[2/3] revival_patcher.dll → src/patcher/
[3/3] revival_wrapper.exe → src/wrapper/
```

Tek bileşen build:

```bat
cd src\tool    && build.bat
cd src\patcher && build.bat
cd src\wrapper && build.bat
```

Her `build.bat` kendi `vcvars32` ortamını set eder; Developer Command Prompt gerekmez.

## Backend services build

```bat
cd server
make build
```

Alternatif:

```bat
go build -o bin/ ./cmd/...
```

Çıktı: `server/bin/` altında servis binary'leri.

## Derleme parametreleri

| Parametre | Değer | Gerekçe |
|-----------|-------|---------|
| Machine | X86 | Hedef binary 32-bit |
| CRT linking | /MT (statik) | vcruntime140.dll bağımlılığı yok |
| Bitness | 32-bit (tüm client bileşenleri) | Process injection, CONTEXT okuma |

## Build doğrulama (smoke test)

Build sonrası minimum doğrulama:

```bat
src\tool\revival_tool.exe ping
:: Beklenen: ok

src\tool\revival_tool.exe help
:: Beklenen: komut listesi
```

Backend:

```bat
cd server
dir bin\*.exe
:: Beklenen: entry-server, lobby-server, battle-server, daum-auth, patch-server, launcher-web
```

## Bilinen kısıtlar

- Client build yalnızca Windows üzerinde yapılabilir.
- Backend build platform-bağımsızdır; runtime Windows hedeflidir.
- Build sırasında yönetici yetkisi gerekmez; runtime'da gereklidir.

## İlgili belgeler

- [deployment.md](deployment.md)
- [configuration.md](configuration.md)
- [../architecture/client-stack.md](../architecture/client-stack.md)
