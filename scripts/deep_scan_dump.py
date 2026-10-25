"""Deep scan of dumped regions to find the real decrypted .text section.
The 30MB region at 0x7ff7925db000 starts with encrypted data but might contain
decrypted code further in. Also scan the minidump for module list."""
import os, sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6"

# Scan the 30MB EXECUTE region for real code
big_file = os.path.join(OUT_DIR, "r_00007ff7925db000_01dfd000_p20_t1000000.bin")
with open(big_file, "rb") as f:
    data = f.read()

print(f"=== 30MB region scan ({len(data)} bytes) ===")
# Check every 1MB for code patterns
for i in range(0, len(data), 0x100000):
    chunk = data[i:i+0x100000]
    prologues = chunk.count(b'\x48\x89\x5c\x24')
    calls = chunk.count(b'\xe8') + chunk.count(b'\xff\x15')
    # Check for MZ
    mz = b'MZ' in chunk[:0x1000] if i == 0 else False
    # Check for printable strings
    ascii_strings = len(re.findall(rb'[\x20-\x7e]{8,}', chunk))
    # Entropy check (simple)
    zeros = chunk.count(b'\x00')
    nonzero_ratio = 1 - zeros / len(chunk) if len(chunk) > 0 else 0
    
    if prologues > 10 or ascii_strings > 50 or mz:
        print(f"  offset 0x{i:x} (0x{i//1048576}MB): prologues={prologues}, calls={calls}, strings={ascii_strings}, nonzero={nonzero_ratio:.1%}, MZ={mz}")

# Also scan the 15.8MB region
big_file2 = os.path.join(OUT_DIR, "r_00007ff7a27da000_00fc6000_p20_t1000000.bin")
with open(big_file2, "rb") as f:
    data2 = f.read()

print(f"\n=== 15.8MB region scan ({len(data2)} bytes) ===")
for i in range(0, len(data2), 0x100000):
    chunk = data2[i:i+0x100000]
    prologues = chunk.count(b'\x48\x89\x5c\x24')
    ascii_strings = len(re.findall(rb'[\x20-\x7e]{8,}', chunk))
    qt_hits = sum(1 for s in [b'Qt6', b'QApp', b'QObject', b'QWidget', b'boost', b'asio', b'Axon', b'Desk'] if s in chunk)
    if prologues > 5 or qt_hits > 0 or ascii_strings > 50:
        print(f"  offset 0x{i:x} (0x{i//1048576}MB): prologues={prologues}, strings={ascii_strings}, qt={qt_hits}")

# Scan the 113.8MB WRITECOPY region
big_file3 = os.path.join(OUT_DIR, "r_00007ff79b522000_071c9000_p80_t1000000.bin")
if os.path.exists(big_file3):
    with open(big_file3, "rb") as f:
        data3 = f.read(0x800000)  # First 8MB
    print(f"\n=== 113.8MB WRITECOPY region scan (first 8MB) ===")
    for i in range(0, len(data3), 0x100000):
        chunk = data3[i:i+0x100000]
        prologues = chunk.count(b'\x48\x89\x5c\x24')
        ascii_strings = len(re.findall(rb'[\x20-\x7e]{8,}', chunk))
        qt_hits = sum(1 for s in [b'Qt6', b'QApp', b'QObject', b'Axon', b'Desk', b'boost'] if s in chunk)
        if prologues > 5 or qt_hits > 0 or ascii_strings > 50:
            print(f"  offset 0x{i:x} (0x{i//1048576}MB): prologues={prologues}, strings={ascii_strings}, qt={qt_hits}")

# Parse minidump module list
print(f"\n=== Minidump module list ===")
md_file = os.path.join(OUT_DIR, "full.dmp")
with open(md_file, "rb") as f:
    sig = f.read(4)
    if sig == b'MDMP':
        f.seek(0)
        # MINIDUMP_HEADER
        hdr = f.read(32)
        sig_val, ver1, ver2, ver3, ver4, num_streams, stream_dir_rva, checksum, timestamp, flags = struct.unpack_from('<4sIIIIIIIQII', hdr, 0)
        print(f"  Signature: {sig_val}")
        print(f"  Streams: {num_streams}")
        print(f"  Stream dir RVA: 0x{stream_dir_rva:x}")
        
        f.seek(stream_dir_rva)
        for i in range(num_streams):
            # MINIDUMP_DIRECTORY: StreamType(4), DataSize(4), RVA(4)
            st, ds, rva = struct.unpack_from('<III', f.read(12))
            if st == 4:  # ModuleListStream
                print(f"  Found ModuleListStream at RVA 0x{rva:x}")
                save_pos = f.tell()
                f.seek(rva)
                num_modules = struct.unpack_from('<I', f.read(4))[0]
                print(f"  Modules: {num_modules}")
                # Read first 10 modules
                for j in range(min(num_modules, 20)):
                    # MINIDUMP_MODULE: BaseOfImage(8), SizeOfImage(4), CheckSum(4), TimeDateStamp(4), ModuleNameRva(4), VsFixedFileInfo(52), LocationDescriptor(8), ...
                    base, size, cs, tds, name_rva = struct.unpack_from('<QIIII', f.read(24))
                    f.read(52+8)  # skip VsFixedFileInfo + CvRecord
                    # Get name
                    name_pos = f.tell()
                    f.seek(name_rva)
                    name_len = struct.unpack_from('<I', f.read(4))[0]
                    name = f.read(name_len).decode('utf-16-le', errors='replace')
                    f.seek(name_pos)
                    # Skip MiscRecord
                    f.read(8)
                    # Skip remaining fields
                    f.read(8*2)  # Reserved0, Reserved1
                    print(f"    [{j}] 0x{base:x} size=0x{size:x} ({size/1048576:.1f}MB) {name}")
                f.seek(save_pos)
