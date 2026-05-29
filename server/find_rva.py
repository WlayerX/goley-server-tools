import os
import struct

def find_rva_info():
    ntdll_path = r"C:\Windows\SysWOW64\ntdll.dll"
    if not os.path.exists(ntdll_path):
        ntdll_path = r"C:\Windows\System32\ntdll.dll"
    
    if not os.path.exists(ntdll_path):
        print("ntdll.dll not found")
        return
        
    print(f"Reading {ntdll_path}...")
    with open(ntdll_path, "rb") as f:
        data = f.read()
        
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
    magic = struct.unpack("<H", data[pe_offset+24:pe_offset+26])[0]
    is_64 = (magic == 0x20b)
    
    # Correct offsets for Data Directories in Optional Header:
    # PE32 (32-bit): optional header is 224 bytes, export dir is at offset 96.
    # PE32+ (64-bit): optional header is 240 bytes, export dir is at offset 112.
    # Optional header starts at pe_offset + 24.
    data_dir_offset = pe_offset + 24 + (112 if is_64 else 96)
    export_rva, export_size = struct.unpack("<II", data[data_dir_offset:data_dir_offset+8])
    
    print(f"PE is {'64-bit' if is_64 else '32-bit'}")
    print(f"Export RVA: 0x{export_rva:X}, Size: 0x{export_size:X}")
    
    num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
    size_of_optional_header = struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]
    section_table_offset = pe_offset + 24 + size_of_optional_header
    
    sections = []
    export_file_offset = 0
    for i in range(num_sections):
        offset = section_table_offset + i * 40
        name = data[offset:offset+8].split(b'\x00')[0].decode('latin-1')
        misc, rva, size, raw_addr = struct.unpack("<IIII", data[offset+8:offset+24])
        sections.append((name, rva, size, raw_addr))
        if rva <= export_rva < rva + size:
            export_file_offset = raw_addr + (export_rva - rva)
            
    if not export_file_offset:
        print("Export directory not found in sections")
        return
        
    def rva_to_offset(rva):
        for name, sec_rva, sec_size, raw_addr in sections:
            if sec_rva <= rva < sec_rva + sec_size:
                return raw_addr + (rva - sec_rva)
        return 0

    num_names = struct.unpack("<I", data[export_file_offset+24:export_file_offset+28])[0]
    addr_funcs = struct.unpack("<I", data[export_file_offset+28:export_file_offset+32])[0]
    addr_names = struct.unpack("<I", data[export_file_offset+32:export_file_offset+36])[0]
    addr_ords = struct.unpack("<I", data[export_file_offset+36:export_file_offset+40])[0]
    
    funcs_offset = rva_to_offset(addr_funcs)
    names_offset = rva_to_offset(addr_names)
    ords_offset = rva_to_offset(addr_ords)
    
    # Pre-read entire names and ords array to make it fast
    name_rvas = struct.unpack(f"<{num_names}I", data[names_offset:names_offset + num_names*4])
    ord_idxs = struct.unpack(f"<{num_names}H", data[ords_offset:ords_offset + num_names*2])
    
    # Cache all export RVAs
    num_funcs = struct.unpack("<I", data[export_file_offset+20:export_file_offset+24])[0]
    func_rvas = struct.unpack(f"<{num_funcs}I", data[funcs_offset:funcs_offset + num_funcs*4])
    
    # Locate NtTerminateProcess
    nt_term_rva = None
    all_exports = []
    
    print(f"Parsing {num_names} names...")
    for i, name_rva in enumerate(name_rvas):
        name_offset = rva_to_offset(name_rva)
        # Find null terminator
        end = name_offset
        while data[end] != 0:
            end += 1
        name = data[name_offset:end].decode('latin-1')
        
        ord_idx = ord_idxs[i]
        rva = func_rvas[ord_idx]
        all_exports.append((name, rva))
        
        if name == "NtTerminateProcess":
            nt_term_rva = rva
            
    if nt_term_rva is None:
        print("NtTerminateProcess not found in exports")
        return
        
    print(f"NtTerminateProcess RVA: 0x{nt_term_rva:X}")
    target_rva = nt_term_rva - 0xBCA3
    print(f"Target RVA: 0x{target_rva:X}")
    
    all_exports.sort(key=lambda x: x[1])
    closest = None
    for name, rva in all_exports:
        if rva <= target_rva:
            closest = (name, rva)
        else:
            break
            
    if closest:
        print(f"Closest export before Target: {closest[0]} @ RVA 0x{closest[1]:X} (diff: 0x{target_rva - closest[1]:X})")
    else:
        print("No closest export found")
        
    after = None
    for name, rva in all_exports:
        if rva > target_rva:
            after = (name, rva)
            break
    if after:
        print(f"Closest export after Target: {after[0]} @ RVA 0x{after[1]:X} (diff: 0x{after[1] - target_rva:X})")
        
    target_offset = rva_to_offset(target_rva)
    if target_offset:
        target_bytes = data[target_offset:target_offset+16]
        hex_str = " ".join(f"{b:02X}" for b in target_bytes)
        print(f"Bytes at target offset: {hex_str}")
        
if __name__ == "__main__":
    find_rva_info()
