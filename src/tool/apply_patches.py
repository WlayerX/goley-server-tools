#!/usr/bin/env python3
"""
apply_patches.py

patches.json içindeki bütün statik patch'leri verilen bir input
binary'e uygular. IDA Pro gerektirmiyor; sadece JSON + PE section table
parsing kullanıyor.

Bu script normalde `revival_tool patch` komutu tarafından çağrılır, ama
elle de çalıştırabilirsin:

    python apply_patches.py
        [--src C:\\Joygame\\Goley\\BinaryTr\\unpacked_Goley_.exe]
        [--dst C:\\Joygame\\Goley\\BinaryTr\\unpacked_Goley_PATCHED.exe]
        [--patches patches.json]

--src ve --dst belirtilmezse patches.json içindeki "target" bölümü
varsayılan olarak kullanılır.

Python 3.8+ gerektirir, başka bağımlılık yok.
"""

import argparse
import json
import os
import shutil
import struct
import sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATCHES_JSON = os.path.join(THIS_DIR, "patches.json")


def rva_to_file_offset(pe_bytes, rva):
    """PE section table'i kullanarak RVA -> file offset map'le."""
    # DOS header'da e_lfanew (offset 0x3C).
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    # PE header: 4-byte signature + IMAGE_FILE_HEADER (20 byte) sonrasi
    # IMAGE_OPTIONAL_HEADER (size IMAGE_FILE_HEADER+16'da).
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe_bytes, coff_off + 2)[0]
    size_of_opt  = struct.unpack_from("<H", pe_bytes, coff_off + 16)[0]
    sect_off = coff_off + 20 + size_of_opt

    for i in range(num_sections):
        s = sect_off + i * 40
        virt_size  = struct.unpack_from("<I", pe_bytes, s + 8)[0]
        virt_addr  = struct.unpack_from("<I", pe_bytes, s + 12)[0]
        raw_size   = struct.unpack_from("<I", pe_bytes, s + 16)[0]
        raw_offset = struct.unpack_from("<I", pe_bytes, s + 20)[0]
        end_rva = virt_addr + max(virt_size, raw_size)
        if virt_addr <= rva < end_rva:
            return rva - virt_addr + raw_offset
    return None


def apply_patches(src_path, dst_path, patches_json):
    if not os.path.isfile(src_path):
        sys.exit(f"input binary bulunamadi: {src_path}")
    if not os.path.isfile(patches_json):
        sys.exit(f"patches.json bulunamadi: {patches_json}")

    with open(patches_json, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    image_base = int(cfg["target"]["image_base"], 16)
    patches = cfg.get("patches", [])
    print(f"Loaded {len(patches)} patch(es) from {patches_json}")
    print(f"src = {src_path}")
    print(f"dst = {dst_path}")

    shutil.copyfile(src_path, dst_path)
    with open(dst_path, "r+b") as f:
        pe_bytes = f.read()
        applied = 0
        for p in patches:
            ea  = int(p["addr"], 16)
            rva = ea - image_base
            off = rva_to_file_offset(pe_bytes, rva)
            if off is None:
                print(f"  SKIP {p['id']} - RVA 0x{rva:X} mapping yapilamadi")
                continue
            data = bytes.fromhex(p["patched"])
            declared = p.get("size", len(data))
            if len(data) != declared:
                print(f"  WARN {p['id']} - patched bytes ({len(data)}) != declared size ({declared})")
            f.seek(off)
            f.write(data)
            applied += 1
            print(f"  applied {p['id']}: {len(data)} byte, file offset 0x{off:X} (EA 0x{ea:X})")

    print(f"OK - {applied}/{len(patches)} patch uygulandi, yazildi: {dst_path}")
    return applied == len(patches)


def main():
    ap = argparse.ArgumentParser(
        description="Standalone IDA-gerektirmeyen binary patch uygulayici.",
    )
    ap.add_argument("--src",     help="input binary (yoksa patches.json'dan)")
    ap.add_argument("--dst",     help="output binary (yoksa patches.json'dan)")
    ap.add_argument("--patches", default=DEFAULT_PATCHES_JSON,
                    help=f"patches.json yolu (varsayilan: {DEFAULT_PATCHES_JSON})")
    args = ap.parse_args()

    if not os.path.isfile(args.patches):
        sys.exit(f"patches.json bulunamadi: {args.patches}")

    with open(args.patches, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    src = args.src or cfg["target"]["input"]
    dst = args.dst or cfg["target"]["output"]

    ok = apply_patches(src, dst, args.patches)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
