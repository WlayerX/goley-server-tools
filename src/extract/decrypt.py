"""
Goley'in şifreli oyun dosyalarını (VLH/VLD çiftleri) açan script.

Goley dosyalarını Anipark kendi yazdığı bir cipher ile şifrelemiş.
Cipher bir TEA delta sabiti ve Blowfish tarzı S-box'lar kullanıyor.
Tam reverse etmek yerine, Goley'in kendi decrypt fonksiyonunu
goley_real_code.bin'den okuyup Unicorn x86 emulator'de çalıştırıyoruz.
Bu daha güvenli, çünkü Anipark eğer cipher'da bir bug bıraktıysa ya da
özel bir buffer overflow durumu varsa, biz de aynısına takılıyoruz.
Yani sonuç oyunun kendi runtime'ında gördüğü ne ise, bizim gördüğümüz
de o.

Şifre çözme akışı (her VLH+VLD çifti için):
  1. Master key  = MD5("VolanteEncryptKey_84106141")
     Bu Anipark'ın bütün VLH dosyaları için sabit anahtarı.
  2. VLH dosyasını master key ile çözeriz, içindeki dosya tablosunu
     elde ederiz.
  3. VLH'in içindeki tablonun başında 16 byte uzunluğunda ASCII bir
     anahtar var (her dosya için farklı).
  4. VLD key = MD5(VLH içindeki ASCII anahtar)
  5. VLD'yi bu anahtarla çözeriz, içinden zlib stream'lerini çıkarırız.
  6. Her zlib stream VLH tablosundaki dosya adına karşılık gelir.

Kullanım:
  python decrypt.py <vlh_dosyasi> <vld_dosyasi> <cikti_klasoru>
  python decrypt.py --all <oyun_data_klasoru> <cikti_kok>

Bağımlılık:
  pip install unicorn
"""

import argparse
import hashlib
import io
import os
import re
import struct
import sys
import zlib
from pathlib import Path

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
    from unicorn.x86_const import (
        UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EDX,
    )
except ImportError:
    sys.exit(
        "Unicorn paketi yuklu degil. Kurmak icin:\n"
        "  pip install unicorn"
    )

# UTF-8 output (Korece dosya isimleri vs.)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Goley'in kendi decrypt fonksiyonu binary olarak yaninda duruyor.
# Bu dosya RE asamasinda Goley_.exe'nin unpacked memory dump'indan
# cikartildi (tek seferlik is, sonraki acilislarda yine kullanilir).
THIS_DIR = Path(__file__).resolve().parent
CODE_BIN = THIS_DIR / "goley_real_code.bin"

# Goley_.exe'nin image base'i ve bizim ilgilendigimiz iki fonksiyonun
# unpacked memory'deki adresleri. Bunlar IDA'da bulup not aldigimiz
# sabit degerler.
CODE_BASE = 0x401000
KEY_SCHEDULE_VA = 0x4194c0   # 16-byte anahtardan 128-byte round-key tablosunu ureten fonksiyon
DECRYPT_BLOCK_VA = 0x4185f0  # tek bir 16-byte blok'u decrypt eden fonksiyon


def setup_emulator():
    """Unicorn'u Goley'in decrypt kodu yuklenmis sekilde baslatir."""
    if not CODE_BIN.is_file():
        sys.exit(
            f"goley_real_code.bin bulunamadi: {CODE_BIN}\n"
            f"Bu dosya repoya commit edilmis olmali (1.7 MB binary blob)."
        )

    code = CODE_BIN.read_bytes()
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(0x00400000, 0x300000, UC_PROT_ALL)   # Goley_ kod alani
    mu.mem_map(0x10000000, 0x10000, UC_PROT_ALL)    # stack
    mu.mem_map(0x20000000, 0x10000, UC_PROT_ALL)    # data buffer
    mu.mem_write(CODE_BASE, code)
    return mu


def make_round_keys(mu, key16):
    """16-byte anahtardan 128-byte round-key tablosu uret."""
    KEY_IN = 0x20000000
    KEY_OUT = 0x20000100
    mu.mem_write(KEY_IN, key16)
    mu.mem_write(KEY_OUT, b"\x00" * 128)
    stack = 0x10000000 + 0x10000 - 0x100 - 4
    mu.mem_write(stack, b"\xff\xff\xff\xff")
    mu.reg_write(UC_X86_REG_ESP, stack)
    mu.reg_write(UC_X86_REG_EBP, stack + 8)
    mu.reg_write(UC_X86_REG_EDX, KEY_IN)
    mu.reg_write(UC_X86_REG_EAX, KEY_OUT)
    try:
        mu.emu_start(KEY_SCHEDULE_VA, 0xfffffffe, count=10000)
    except Exception:
        pass
    return bytes(mu.mem_read(KEY_OUT, 128))


def decrypt_block(mu, round_keys, block16):
    """Tek bir 16-byte blok'u round-key tablosu ile decrypt eder."""
    RK = 0x20000200
    DATA = 0x20000300
    mu.mem_write(RK, round_keys)
    mu.mem_write(DATA, block16)
    stack = 0x10000000 + 0x10000 - 0x200
    stack -= 4
    mu.mem_write(stack, struct.pack("<I", DATA))
    stack -= 4
    mu.mem_write(stack, b"\xff\xff\xff\xff")
    mu.reg_write(UC_X86_REG_ESP, stack)
    mu.reg_write(UC_X86_REG_EBP, stack + 8)
    mu.reg_write(UC_X86_REG_EAX, RK)
    try:
        mu.emu_start(DECRYPT_BLOCK_VA, 0xfffffffe, count=50000)
    except Exception:
        pass
    return bytes(mu.mem_read(DATA, 16))


def decrypt_buffer(mu, round_keys, data):
    """Hizali bir buffer'i 16'lik bloklar halinde decrypt eder."""
    out = bytearray()
    aligned_len = (len(data) // 16) * 16
    for i in range(0, aligned_len, 16):
        out.extend(decrypt_block(mu, round_keys, data[i:i + 16]))
    return bytes(out)


def extract_paths(vlh_index):
    """VLH index tablosundan dosya yollarini cikar."""
    # Iki yaygin pattern: "Data/foo.ext" veya direkt "foo.ext"
    patterns = [
        rb"Data/[^\x00]+\.[A-Za-z]{2,5}",
        rb"[A-Za-z][^\x00/]+\.[A-Za-z]{2,5}",
    ]
    for pat in patterns:
        matches = list(re.finditer(pat, vlh_index))
        if matches:
            return [m.group().decode("ascii", "replace") for m in matches]
    return []


def process_pair(mu, vlh_path, vld_path, out_dir, master_rk):
    """Bir VLH + VLD ciftini cozer, ciktilarini out_dir altina yazar."""
    print(f"\n{'=' * 60}")
    print(f"VLH: {vlh_path.name}")
    print(f"VLD: {vld_path.name if vld_path.exists() else '(yok)'}")
    print("=" * 60)

    vlh_raw = vlh_path.read_bytes()
    print(f"VLH boyut: {len(vlh_raw)} byte")

    # VLH formati: ilk 24 byte header (clear), gerisi sifreli body.
    body = vlh_raw[24:]
    body_aligned = body[:(len(body) // 16) * 16]
    print(f"Cozuluyor: {len(body_aligned)} byte ({len(body_aligned) // 16} blok)")
    vlh_dec = decrypt_buffer(mu, master_rk, body_aligned)

    # Body bazen zlib ile de sikistirilmis.
    if vlh_dec[:2] in (b"\x78\xda", b"\x78\x9c", b"\x78\x01"):
        print("VLH body zlib ile sikistirilmis, aciliyor...")
        try:
            vlh_idx = zlib.decompress(vlh_dec)
        except zlib.error as e:
            print(f"zlib decompress basarisiz: {e}")
            return
    else:
        vlh_idx = vlh_dec

    # VLH'in basindaki 4 byte: ASCII anahtarin uzunlugu (1-256 arasi olmali).
    try:
        keylen = struct.unpack("<I", vlh_idx[0:4])[0]
        if not (1 <= keylen <= 256):
            print(f"VLH header'inda mantiksiz keylen={keylen}, atlanyor")
            return
        embedded_key = vlh_idx[4:4 + keylen]
        print(f"VLH icindeki anahtar (uzunluk {keylen}): {embedded_key!r}")
    except Exception as e:
        print(f"VLH header okunamadi: {e}")
        return

    paths = extract_paths(vlh_idx)
    print(f"VLH icinde {len(paths)} dosya yolu bulundu")
    for p in paths[:5]:
        print(f"  {p}")
    if len(paths) > 5:
        print(f"  ... ve {len(paths) - 5} tane daha")

    if not vld_path.exists():
        print("(VLD yok, sadece index okundu)")
        return

    # VLD'yi VLH'in icindeki anahtar ile cozeriz.
    vld_raw = vld_path.read_bytes()
    print(f"\nVLD boyut: {len(vld_raw)} byte")
    vld_key = hashlib.md5(embedded_key).digest()
    vld_rk = make_round_keys(mu, vld_key)
    vld_dec_aligned = (len(vld_raw) // 16) * 16
    print(f"Cozuluyor: {vld_dec_aligned // 16} blok")
    vld_dec = decrypt_buffer(mu, vld_rk, vld_raw[:vld_dec_aligned])

    # VLD'nin icinde arka arkaya zlib stream'leri var, her biri bir dosya.
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    offset = 0
    idx = 0
    while offset < len(vld_dec) - 4:
        # zlib magic byte'i 0x78. Yoksa bir sonraki zlib basini ara.
        if vld_dec[offset] != 0x78:
            nxt = -1
            for j in range(offset, min(len(vld_dec) - 1, offset + 128)):
                if vld_dec[j] == 0x78 and vld_dec[j + 1] in (0x01, 0x9c, 0xda, 0x5e):
                    nxt = j
                    break
            if nxt < 0:
                break
            offset = nxt
            continue
        decomp = zlib.decompressobj()
        try:
            payload = decomp.decompress(vld_dec[offset:])
            consumed = len(vld_dec) - offset - len(decomp.unused_data)
            if idx < len(paths):
                fname = Path(paths[idx].replace("\\", "/")).name
            else:
                fname = f"unknown_{idx:03d}.bin"
            (out_dir / fname).write_bytes(payload)
            extracted += 1
            offset += consumed
            idx += 1
        except zlib.error:
            offset += 1

    print(f"Cikarilan dosya sayisi: {extracted}")
    print(f"Konum: {out_dir}")


def find_pairs(data_dir):
    """data_dir icindeki tum VLH+VLD ciftlerini bulur."""
    vlh_files = sorted(data_dir.glob("*.VLH")) + sorted(data_dir.glob("*.vlh"))
    pairs = []
    for vlh in vlh_files:
        vld = vlh.with_suffix(".VLD")
        if not vld.is_file():
            vld = vlh.with_suffix(".vld")
        pairs.append((vlh, vld))
    return pairs


def main():
    ap = argparse.ArgumentParser(
        description="Goley VLH/VLD ciftlerini cozer (Anipark cipher, Unicorn emulasyonu).",
    )
    ap.add_argument("--all", metavar="DATA_DIR", type=Path,
                    help="DATA_DIR icindeki tum VLH+VLD ciftlerini cozer")
    ap.add_argument("--out", metavar="OUT_DIR", type=Path, default=Path("extracted"),
                    help="cikti kok dizini (varsayilan: ./extracted)")
    ap.add_argument("vlh", nargs="?", type=Path, help="tek VLH dosyasi")
    ap.add_argument("vld", nargs="?", type=Path, help="tek VLD dosyasi")
    args = ap.parse_args()

    mu = setup_emulator()
    master_key = hashlib.md5(b"VolanteEncryptKey_84106141").digest()
    master_rk = make_round_keys(mu, master_key)
    print(f"Master key (sabit): {master_key.hex()}")
    print("Round key tablosu hazir.")

    if args.all:
        if not args.all.is_dir():
            sys.exit(f"Dizin yok: {args.all}")
        pairs = find_pairs(args.all)
        if not pairs:
            sys.exit(f"{args.all} icinde VLH dosyasi bulunamadi")
        print(f"{len(pairs)} cift bulundu")
        for vlh, vld in pairs:
            out_sub = args.out / vlh.stem.lower()
            process_pair(mu, vlh, vld, out_sub, master_rk)
        return

    if args.vlh is None:
        ap.print_help()
        sys.exit(1)

    vld = args.vld if args.vld else args.vlh.with_suffix(".VLD")
    out_sub = args.out / args.vlh.stem.lower()
    process_pair(mu, args.vlh, vld, out_sub, master_rk)


if __name__ == "__main__":
    main()
