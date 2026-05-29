# Konfigürasyon

## Ortam değişkenleri

| Değişken | Varsayılan | Kapsam | Açıklama |
|----------|------------|--------|----------|
| `GOLEY_INSTALL_DIR` | `C:\Joygame\Goley\BinaryTr` | Client | Goley kurulum dizini |
| `GOLEY_LOG_LEVEL` | `info` | Backend | Log seviyesi (`debug`, `info`, `warn`, `error`) |
| `GLY_NO_WRAPPER` | — | Wrapper | IFEO recursion guard; wrapper tarafından set edilir |

## Yol çözümlemesi

Hardcoded path kullanılmaz. Tüm client bileşenleri runtime'da kendi konumlarını tespit eder:

| Bileşen | Yöntem | Depo kökü |
|---------|--------|-----------|
| revival_tool.exe | `GetModuleFileNameA` → 2 seviye yukarı | `<repo>/` |
| revival_patcher.dll | `GetModuleFileNameA` (DllMain) | Log: `<repo>/patcher.log` |
| revival_wrapper.exe | `wmain` başında self-path | DLL ve log path türetimi |

Depo herhangi bir konuma clone edilebilir; yol bağımlılığı oluşmaz.

## IFEO registry

| Anahtar | Değer |
|---------|-------|
| Konum | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Goley_.exe\Debugger` |
| Değer | `"<repo>\src\wrapper\revival_wrapper.exe"` |

Yönetim:

```bat
src\tool\revival_tool.exe ifeo show
src\tool\revival_tool.exe ifeo set
src\tool\revival_tool.exe ifeo clear
```

`init` ve `launch` komutları IFEO'yu otomatik yönetir.

## Patch kataloğu

Statik patch tanımları: `src/tool/patches.json`

İnsan okunabilir referans: [../client/binary-patches.md](../client/binary-patches.md)

Image base varsayımı: `0x00400000`

## Backend konfigürasyonu

Servisler şu an komut satırı flag'leri ve ortam değişkenleri ile yapılandırılır. Kalıcı config dosyası (paths.ini vb.) henüz implement edilmemiştir — bkz. [../project/roadmap.md](../project/roadmap.md).

## Visual Studio yolu

Farklı VS kurulum yolu kullanılıyorsa her build script'te güncellenmesi gereken satır:

```
src/tool/build.bat    → VS_PATH
src/patcher/build.bat → VS_PATH
src/wrapper/build.bat → VS_PATH
```

## Kalıcı ortam değişkeni ayarlama

Oturum bazlı:

```bat
set GOLEY_INSTALL_DIR=D:\Games\Goley\BinaryTr
```

Kalıcı (kullanıcı düzeyi):

```bat
setx GOLEY_INSTALL_DIR "D:\Games\Goley\BinaryTr"
```

## İlgili belgeler

- [deployment.md](deployment.md)
- [../client/cli-reference.md](../client/cli-reference.md)
