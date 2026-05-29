# Goley Server Tools

Özel ağ ortamında Goley istemci–sunucu yığınının uçtan uca çalıştırılması için tasarlanmış platform.

Platform; orijinal istemcinin Windows üzerinde ayağa kaldırılması (client runtime) ile kapalı resmi altyapının yerini alan backend emülasyonunu (backend services) tek depo altında birleştirir. Amaç, dağıtılabilir bir geliştirme ve operasyon tabanı sağlamaktır.

---

## Sistem sınırları

| Dahil | Hariç |
|-------|-------|
| Client runtime araç zinciri (`src/`) | Orijinal oyun binary'leri ve asset dosyaları |
| Backend servis implementasyonu (`server/`) | Resmi Joygame / Anipark sunucu kodu |
| ProudNet protokol re-implementasyonu | Resmi Nettention ProudNet kaynak kodu |
| Merkezi teknik dokümantasyon (`docs/`) | Production ortamı altyapısı (CI, monitoring, secrets) |

Orijinal istemci kurulumu (`GoleySetup.exe`) ve oyun dosyaları operasyon ortamından temin edilir; depo bu bileşenleri içermez ve taşımaz.

---

## Mimari özet

```
┌──────────────────────────────────────────────────────────────┐
│                     goley-private-server                      │
├────────────────────────────┬─────────────────────────────────┤
│      Client Runtime        │       Backend Services           │
│          src/              │           server/                │
├────────────────────────────┼─────────────────────────────────┤
│  revival_tool.exe          │  entry-server        :2270/TCP  │
│  revival_patcher.dll       │  lobby-server        :2271/TCP  │
│  revival_wrapper.exe       │  battle-server       :2272/TCP  │
│  decrypt.py                │  patch-server        :80/HTTP   │
│                            │  launcher-web        :8080/HTTP │
│                            │  daum-auth           :HTTP      │
└────────────────────────────┴─────────────────────────────────┘
                              │
                    ProudNet TCP / UDP
```

**Client runtime** — Themida ve nProtect koruma katmanlarının yönetimi, istemci başlatma, statik patch uygulama ve şifreli oyun verisi (VLH/VLD) çıkarımı.

**Backend services** — Login, lobby, maç eşleştirme, patch dağıtımı ve launcher web arayüzü. Maç mantığı istemci tarafında (P2P); backend authentication, matchmaking ve relay sağlar.

Ayrıntılı mimari: [docs/architecture/overview.md](docs/architecture/overview.md)

---

## Depo organizasyonu

```
goley-private-server/
├── docs/              Tek kaynak dokümantasyon
├── src/               Client runtime (C/C++, x86)
│   ├── tool/          CLI ve orchestration
│   ├── patcher/       Runtime injection DLL
│   ├── wrapper/       IFEO process wrapper
│   └── extract/       Asset decryption
├── server/            Backend services (Go)
│   ├── cmd/           Servis binary'leri
│   ├── internal/      ProudNet stack
│   ├── scripts/       Deployment script'leri
│   └── web/           Launcher ve patch asset'leri
├── build_all.bat      Client runtime build
└── LICENSE
```

---

## Ön koşullar

| Katman | Gereksinim |
|--------|------------|
| İşletim sistemi | Windows 10 veya 11 (x64 host, x86 target) |
| Client derleme | Visual Studio 2022 Build Tools — MSVC v143, x86 |
| Backend derleme | Go 1.22 veya üzeri |
| Asset extraction | Python 3.10+, Unicorn |
| Runtime | Yönetici yetkisi (IFEO registry, process injection) |
| Orijinal istemci | Joygame Goley kurulum paketi (depo dışı) |

Build ve deployment prosedürleri: [docs/operations/build.md](docs/operations/build.md) · [docs/operations/deployment.md](docs/operations/deployment.md)

---

## Kurulum

### 1. Client runtime

```bat
build_all.bat
src\tool\revival_tool.exe init "C:\path\to\GoleySetup.exe"
src\tool\revival_tool.exe launch
```

### 2. Backend services

```bat
cd server
make build
.\scripts\start-all.ps1
.\scripts\setup-hosts.ps1
```

`setup-hosts.ps1` yönetici yetkisi gerektirir. Patch server için orijinal binary'lerin `server/web/launcher/chagu/Real_Server_Patch/` altına kopyalanması gerekir — bkz. [docs/operations/deployment.md](docs/operations/deployment.md).

---

## Implementasyon durumu

| Alan | Durum |
|------|-------|
| Client build ve CLI | Operasyonel |
| Themida runtime bypass | Kısmi — splash ekranına ulaşıldı |
| nProtect handshake | Açık — init thread bloke |
| Backend ProudNet handshake | Mock client ile doğrulandı |
| Gerçek istemci entegrasyonu | Doğrulanmadı |

Güncel durum matrisi, bilinen kısıtlar ve yol haritası: [docs/project/status.md](docs/project/status.md) · [docs/project/roadmap.md](docs/project/roadmap.md)

---

## Dokümantasyon

Tüm teknik referans `docs/` altında merkezi olarak yönetilir. Giriş noktası: [docs/README.md](docs/README.md)

| Rol | Başlangıç belgesi |
|-----|-------------------|
| Mimari | [docs/architecture/overview.md](docs/architecture/overview.md) |
| Operasyon | [docs/operations/deployment.md](docs/operations/deployment.md) |
| Client geliştirme | [docs/client/cli-reference.md](docs/client/cli-reference.md) |
| Backend geliştirme | [docs/server/services.md](docs/server/services.md) |
| Sorun giderme | [docs/operations/runbook.md](docs/operations/runbook.md) |

## Teşekkürler
Projenin geliştirilme sürecini mümkün kılan projeye aşağıda ki bağlantıdan ulaşabilirsiniz.
- github.com/0x1-1/revival 

---

## Lisans

MIT — [LICENSE](LICENSE)

Üçüncü taraf bağımlılıklar: [docs/legal/third-party-licenses.md](docs/legal/third-party-licenses.md)
