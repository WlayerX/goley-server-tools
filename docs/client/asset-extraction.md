# Asset Extraction — VLH/VLD Decryption

## Genel

Goley oyun verilerini `.VLH` + `.VLD` çift formatında saklar. Konum: `C:\Joygame\Goley\Data\`

İçerik: karakter modelleri, stadyum dosyaları, shader'lar, çeviriler.

## Kullanım

### Bağımlılık kurulumu

```bat
pip install -r src\extract\requirements.txt
```

### Tek çift

```bat
python src\extract\decrypt.py ^
    "C:\Joygame\Goley\Data\Character.VLH" ^
    "C:\Joygame\Goley\Data\Character.VLD" ^
    --out extracted
```

### Tüm Data klasörü

```bat
python src\extract\decrypt.py --all "C:\Joygame\Goley\Data" --out extracted
```

### CLI üzerinden

```bat
src\tool\revival_tool.exe extract
src\tool\revival_tool.exe extract "path\to\file.VLH" "path\to\file.VLD"
```

## Şifreleme modeli

Anipark custom cipher. TEA delta sabiti, Blowfish tarzı 256 girişli S-box'lar, 16-byte blok boyutu.

Cipher'ın tam Python port'u yerine Unicorn x86 emulator yaklaşımı tercih edilmiştir: Goley'in kendi decrypt fonksiyonu (`goley_real_code.bin`, 1.7 MB) emulator'de çalıştırılır.

### Anahtar türetme

```
Master key = MD5("VolanteEncryptKey_84106141")     ← tüm VLH'ler için sabit
VLH decrypt → index table → 16-byte ASCII key
VLD key    = MD5(ASCII key)                         ← dosyaya özgü
VLD decrypt → ardışık zlib stream'ler → bireysel dosyalar
```

## Akış diyagramı

```
Character.VLH ──master key──► index table ──ASCII key──► MD5 ──► Character.VLD
                                                                      │
                                                                      ▼
                                                            zlib streams
                                                                      │
                                                                      ▼
                                                        extracted/character/
                                                            Mascot.X
                                                            Player001.X
                                                            ...
```

## goley_real_code.bin

Themida pack'li binary'de decrypt fonksiyonu disk'te okunamaz. Memory dump'tan elde edilmiştir:

- Kaynak: runtime unpack sonrası 0x00400000–0x00580000 aralığı
- `key_schedule`: 0x4194c0
- `decrypt_block`: 0x4185f0

Depo içinde commit edilmiştir; kullanıcının kendi unpack işlemi yapması gerekmez.

IDA analizi: "Load file" → "Binary file", image base 0x401000.

## Çıktı örnekleri

```
extracted/character/     — Karakter modelleri
extracted/stadium/       — Stadyum dosyaları
extracted/translations/
    Korean.txt
    Turkish.txt          — Tam Türkçe çeviri seti
    Chinese.txt          — Boş (Joygame TR dağıtımında dahil edilmemiş)
```

## İlgili belgeler

- [cli-reference.md](cli-reference.md)
- [../architecture/client-stack.md](../architecture/client-stack.md)
