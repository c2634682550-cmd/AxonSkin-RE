import sys, struct, pefile, os

TARGET = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
os.makedirs(OUT, exist_ok=True)

pe = pefile.PE(TARGET, fast_load=True)
pe.parse_data_directories()

print("=== PE parse ===")
print(f"Machine: 0x{pe.FILE_HEADER.Machine:x}")
print(f"EP RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}  ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
print(f"NumSections: {pe.FILE_HEADER.NumberOfSections}")
print(f"SizeOfImage: 0x{pe.OPTIONAL_HEADER.SizeOfImage:x}")

print("\n=== Sections ===")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
    print(f"{name:10} VA=0x{s.VirtualAddress:08x} VS=0x{s.Misc_VirtualSize:08x} "
          f"RawPtr=0x{s.PointerToRawData:08x} RawSize=0x{s.SizeOfRawData:08x} Chars=0x{s.Characteristics:08x}")

# Identify which section holds the entry point
ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
for s in pe.sections:
    if s.VirtualAddress <= ep_rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
        name = s.Name.rstrip(b'\x00').decode('latin1','replace')
        print(f"\nEP 0x{ep_rva:x} is in section {name} (VA=0x{s.VirtualAddress:x}, RawPtr=0x{s.PointerToRawData:x})")
        # EP file offset
        ep_off = s.PointerToRawData + (ep_rva - s.VirtualAddress)
        print(f"EP file offset: 0x{ep_off:x}")
        break

# Raw bytes of each on-disk section
print("\n=== On-disk section bytes ===")
with open(TARGET, 'rb') as f:
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('latin1','replace')
        if s.SizeOfRawData > 0:
            f.seek(s.PointerToRawData)
            b = f.read(min(s.SizeOfRawData, 4096))
            hexs = b[:96].hex(' ')
            asc = ''.join(chr(c) if 32<=c<=126 else '.' for c in b[:96])
            print(f"\n{name}  first 96 bytes (file):")
            print(f"  {hexs}")
            print(f"  |{asc}|")
            # search for LZMA props signature (5 bytes: lc,lp,pb, dict size 4 bytes) typical 0x5d 00 00 00 08 or 0x5d 00 00 10 00
            f.seek(s.PointerToRawData)
            full = f.read(s.SizeOfRawData)
            # LZMA props often start with 0x5d or 0x5c. We look for plausible prop bytes followed by uncompressed size (8 bytes, often big-endian-ish or little-endian)
            for off in range(0, min(len(full), 0x2000)):
                if full[off] in (0x5d, 0x5c, 0x01, 0x00) and off+13 <= len(full):
                    # heuristic: props byte then 4-byte dict then 8-byte usize
                    props = full[off]
                    dsize = struct.unpack('<I', full[off+1:off+5])[0]
                    usize = struct.unpack('<Q', full[off+5:off+13])[0]
                    if 0x1000 <= dsize <= 0x40000000 and 0x1000 <= usize <= 0x100000000:
                        print(f"  candidate LZMA @+0x{off:x}: props=0x{props:02x} dict=0x{dsize:x} usize=0x{usize:x}")
        else:
            print(f"\n{name}  (no disk data)")

# Save section dumps of on-disk sections (capped) for inspection
with open(TARGET, 'rb') as f:
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('latin1','replace')
        if s.SizeOfRawData > 0:
            cap = min(s.SizeOfRawData, 8*1024*1024)
            f.seek(s.PointerToRawData)
            data = f.read(cap)
            with open(os.path.join(OUT, f"sec_{name}.bin"), 'wb') as o:
                o.write(data)
            print(f"saved sec_{name}.bin ({len(data)} bytes)")

# Look for 'MPRESS' markers anywhere
with open(TARGET, 'rb') as f:
    data = f.read()
for marker in [b'MPRESS', b'MPR', b'MPRESS1', b'MPRESS2', b'.MPRESS', b'LZMA']:
    idx = 0
    hits = []
    while True:
        i = data.find(marker, idx)
        if i < 0: break
        hits.append(i)
        idx = i+1
        if len(hits) >= 5: break
    if hits:
        print(f"\nmarker {marker}: hits at {[hex(h) for h in hits]}")

# Tail of file (last 4KB) to check for overlay footer
with open(TARGET, 'rb') as f:
    f.seek(max(0, len(data)-4096))
    tail = f.read(4096)
    asc = ''.join(chr(c) if 32<=c<=126 else '.' for c in tail[-256:])
    print(f"\nLast 256 bytes ascii:\n{asc}")
