"""Manually parse minidump module list with correct struct offsets.
MINIDUMP_MODULE layout (108 bytes):
  0:  ULONG64 BaseOfImage
  8:  ULONG32 SizeOfImage
  12: ULONG32 CheckSum
  16: ULONG32 TimeDateStamp
  20: RVA     ModuleNameRva  <-- was reading from wrong offset!
  24: VS_FIXEDFILEINFO (52 bytes)
  76: MINIDUMP_LOCATION_DESCRIPTOR CvRecord (8 bytes)
  84: MINIDUMP_LOCATION_DESCRIPTOR MiscRecord (8 bytes)
  92: ULONG64 Reserved0
  100: ULONG64 Reserved1
"""
import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

md_file = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6\full.dmp"
with open(md_file, "rb") as f:
    # MINIDUMP_HEADER (32 bytes)
    hdr = f.read(32)
    sig = hdr[:4]
    num_streams = struct.unpack_from('<I', hdr, 8)[0]
    stream_dir_rva = struct.unpack_from('<I', hdr, 12)[0]
    print(f"Sig={sig}, Streams={num_streams}, DirRVA=0x{stream_dir_rva:x}")
    
    # Read stream directory
    f.seek(stream_dir_rva)
    streams = []
    for i in range(num_streams):
        st, ds, rva = struct.unpack_from('<III', f.read(12))
        streams.append((st, ds, rva))
    
    # Find ModuleListStream (type 4)
    for st, ds, rva in streams:
        if st == 4:
            print(f"\nModuleListStream at RVA 0x{rva:x}")
            f.seek(rva)
            num_modules = struct.unpack_from('<I', f.read(4))[0]
            print(f"Modules: {num_modules}\n")
            
            modules = []
            for j in range(num_modules):
                mod_data = f.read(108)
                base = struct.unpack_from('<Q', mod_data, 0)[0]
                size = struct.unpack_from('<I', mod_data, 8)[0]
                cs = struct.unpack_from('<I', mod_data, 12)[0]
                tds = struct.unpack_from('<I', mod_data, 16)[0]
                name_rva = struct.unpack_from('<I', mod_data, 20)[0]
                
                # Read name (MINIDUMP_STRING = ULONG32 Length + WCHAR Buffer[])
                save = f.tell()
                f.seek(name_rva)
                name_len = struct.unpack_from('<I', f.read(4))[0]
                name_bytes = f.read(name_len)
                name = name_bytes.decode('utf-16-le', errors='replace')
                f.seek(save)
                
                modules.append((base, size, name))
            
            # Print all modules sorted by base address
            for base, size, name in sorted(modules):
                if size > 0x100000 or 'axon' in name.lower() or 'DeskHelper' in name or 'sprotect' in name.lower():
                    print(f"  0x{base:016x} size=0x{size:08x} ({size/1048576:8.1f}MB) {name}")
            
            # Find the main module (largest with AxonSkin in name or at expected base)
            print("\n=== Looking for main module ===")
            # Check known base from previous dumps: 0x7ff7925db000 or 0x7ff78e700000
            for base, size, name in modules:
                if 'AxonSkin' in name or 'DeskHelper' in name:
                    print(f"  MAIN: 0x{base:016x} size=0x{size:x} ({size/1048576:.1f}MB) {name}")
            
            # Also look for modules at 0x7ff7925xxx000 (our 30MB EXECUTE region base)
            for base, size, name in modules:
                if 0x7ff792500000 <= base <= 0x7ff793000000:
                    print(f"  MATCH 30MB: 0x{base:016x} size=0x{size:x} ({size/1048576:.1f}MB) {name}")
            
            break

# Now extract the .text section from the minidump
# We know the 30MB EXECUTE region starts at 0x7ff7925db000
# This is likely the main module. Let's read PE headers from minidump.
print("\n=== Reading PE headers from minidump ===")
with open(md_file, "rb") as f:
    # Re-parse to get memory list
    f.seek(stream_dir_rva)
    streams2 = []
    for i in range(num_streams):
        st, ds, rva = struct.unpack_from('<III', f.read(12))
        streams2.append((st, ds, rva))
    
    # Find MemoryListStream (type 5) or Memory64ListStream (type 9)
    for st, ds, rva in streams2:
        if st == 9:  # Memory64ListStream
            print(f"Memory64ListStream at RVA 0x{rva:x}")
            f.seek(rva)
            num_ranges = struct.unpack_from('<Q', f.read(8))[0]
            base_rva = struct.unpack_from('<Q', f.read(8))[0]
            print(f"  Ranges: {num_ranges}, BaseRVA: 0x{base_rva:x}")
            
            # Read all ranges, find one containing 0x7ff7925db000
            cur_offset = base_rva
            target_base = 0x7ff7925db000
            target_file_offset = None
            target_size = None
            
            for j in range(num_ranges):
                start = struct.unpack_from('<Q', f.read(8))[0]
                size = struct.unpack_from('<Q', f.read(8))[0]
                
                if start <= target_base < start + size:
                    target_file_offset = cur_offset + (target_base - start)
                    target_size = size
                    print(f"  Found! Range 0x{start:x}-0x{start+size:x}, target at file offset 0x{target_file_offset:x}")
                    break
                cur_offset += size
            
            if target_file_offset:
                # Read PE headers
                f.seek(target_file_offset)
                mz = f.read(2)
                print(f"  At target_base: {mz.hex()} ({'MZ!' if mz == b'MZ' else 'not MZ'})")
                
                # Read more
                f.seek(target_file_offset)
                pe_hdr = f.read(0x400)
                if pe_hdr[:2] == b'MZ':
                    e_lfanew = struct.unpack_from('<I', pe_hdr, 0x3C)[0]
                    print(f"  e_lfanew = 0x{e_lfanew:x}")
                    if pe_hdr[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                        num_sections = struct.unpack_from('<H', pe_hdr, e_lfanew+6)[0]
                        opt_size = struct.unpack_from('<H', pe_hdr, e_lfanew+20)[0]
                        print(f"  Sections: {num_sections}, OptSize: 0x{opt_size:x}")
                        sec_table = e_lfanew + 24 + opt_size
                        for i in range(num_sections):
                            s = pe_hdr[sec_table + i*40 : sec_table + (i+1)*40]
                            if len(s) >= 40:
                                sname = s[:8].rstrip(b'\x00').decode('ascii','replace')
                                vsize = struct.unpack_from('<I', s, 8)[0]
                                va = struct.unpack_from('<I', s, 12)[0]
                                rawsize = struct.unpack_from('<I', s, 16)[0]
                                chars = struct.unpack_from('<I', s, 36)[0]
                                print(f"  Section {sname:10s} VA=0x{va:08x} VSize=0x{vsize:08x} ({vsize/1048576:.1f}MB) RawSize=0x{rawsize:08x} Chars=0x{chars:08x}")
                                
                                if sname == '.text' and vsize > 0x100000:
                                    # Extract this section from minidump
                                    text_file_offset = target_file_offset + va  # In dump, sections are at file offset = module_base_file_offset + section_VA (approximately)
                                    # Actually in a minidump, memory is stored linearly. The range we found starts at target_base.
                                    # .text VA = 0x1000 typically, so it's at target_base + 0x1000
                                    # In the file, that's target_file_offset + 0x1000
                                    # But the range might not cover the full section
                                    text_offset = target_file_offset + va
                                    print(f"  -> Extracting .text from file offset 0x{text_offset:x}")
                                    f.seek(text_offset)
                                    text_data = f.read(min(vsize, 0x3000000))  # Read up to 48MB
                                    print(f"  -> Read {len(text_data)/1048576:.1f}MB")
                                    
                                    # Check for real code
                                    prologues = text_data[:0x100000].count(b'\x48\x89\x5c\x24')
                                    print(f"  -> Prologues in 1st MB: {prologues}")
                                    
                                    # Save
                                    out = os.path.join(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6", "main_text_decrypted.bin")
                                    with open(out, "wb") as f2:
                                        f2.write(text_data)
                                    print(f"  -> Saved to {out} ({len(text_data)/1048576:.1f}MB)")
                    else:
                        print(f"  No PE sig at e_lfanew, got: {pe_hdr[e_lfanew:e_lfanew+4].hex()}")
                else:
                    # Try scanning for MZ within the first few MB
                    print(f"  No MZ at base. Scanning...")
                    for scan in range(0, 0x100000, 0x1000):
                        if pe_hdr[scan:scan+2] == b'MZ' if scan < len(pe_hdr)-1 else False:
                            print(f"    Found MZ at offset 0x{scan:x}")
                            break
            break
