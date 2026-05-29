# Binary Patch Kataloğu

## Genel

Statik patch'ler yalnızca unpacked binary (`unpacked_Goley_.exe`) üzerine uygulanır. Themida korumalı binary'ye memory patch yapılmaz.

Makine okunabilir tanım: `src/tool/patches.json`
Image base varsayımı: `0x00400000`

## Aktif patch'ler

### P-1: GameGuard error reporter prologue

| Alan | Değer |
|------|-------|
| Hedef | `sub_D393F0` (RVA `0x935666`) |
| Orijinal davranış | `if (strlen(error_buf)) MessageBoxA(...)` |
| Patch | `33 C0 C2 04 00` → `xor eax,eax; ret 4` |
| Etki | Error dialog'ları görünmez; fonksiyon 0 döner |
| Risk | Düşük |

Gerekçe: nProtect dosyaları `GameGuard.disabled/` altında olduğu için init fail eder ve error reporter dialog tetikler.

### P-2: nProtect event callback always-success

| Alan | Değer |
|------|-------|
| Hedef | `sub_D35720` (RVA `0x935720`) |
| Orijinal davranış | nProtect event switch table |
| Patch | `B8 01 00 00 00 C2 08 00` → `mov eax,1; ret 8` |
| Etki | Her event success rapor eder |
| Risk | Düşük (case 1019 housekeeping atlanır, pratikte sorun yaratmaz) |

Orijinal switch yapısı:

```
case 1001..1006, 1011..1015: error_buf yaz, init_flag=0, return 0
case 1018, 1019:             return 1
```

### P-3: nProtect event dispatcher (GERİ ALINDI)

| Alan | Değer |
|------|-------|
| Hedef | `sub_8E70E0` (RVA `0x4E70E0`) |
| Denenen patch | `mov eax,1; ret 12` |
| Sonuç | Working Set 42 MB → 26 MB gerileme |
| Gerekçe | Fonksiyon yalnızca translator değil; legitimate init kodu da içerir |
| Durum | `patches.json` → `reverted_patches` listesinde |

## Güvenli patch seti

| ID | Boyut | Adres |
|----|-------|-------|
| P-1 | 5 byte | `0x00935666` |
| P-2 | 8 byte | `0x00935720` |

**Toplam: 13 byte**

P-1 + P-2 ile Working Set 26 MB takılma noktasından 42 MB'a ilerler. Splash ekranına henüz ulaşılamamıştır.

## Patch uygulama

```bat
src\tool\revival_tool.exe patch <input.exe> <output.exe>
```

Arka plan: `apply_patches.py`

Manuel:

```bat
python src\tool\apply_patches.py --src in.exe --dst out.exe
```

Algoritma:
1. `patches.json` oku
2. PE section table → RVA/file offset mapping
3. Patched bytes yaz

## Yeni patch ekleme prosedürü

1. Hedef fonksiyonu disassembler ile analiz et
2. Original ve patched byte'ları belirle
3. `src/tool/patches.json`'a entry ekle
4. Bu belgeye bölüm ekle
5. Test: `patch` + `launch-unpacked`
6. Working Set değişimini izle (artış = ilerleme, gerileme = over-patch)

## Patch güvenlik kuralları

| Kural | Açıklama |
|-------|----------|
| Themida korumalı binary'ye patch yasak | Yalnızca unpacked dump |
| "Always success" patch'leri test et | Fonksiyon legitimate iş yapıyor olabilir |
| Working Set artışı pozitif gösterge | Init pipeline ilerliyor demektir |
| Over-patch geri al | P-3 örneği |

## İlgili belgeler

- [anti-cheat-overview.md](anti-cheat-overview.md)
- [cli-reference.md](cli-reference.md)
- [../project/status.md](../project/status.md)
