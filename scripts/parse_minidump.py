"""Parse minidump module list to find the main module's .text."""
import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

md_file = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6\full.dmp"
with open(md_file, "rb") as f:
    # MINIDUMP_HEADER: 4s(sig) + 4(version) + 4(num_streams) + 4(stream_dir_rva) + 4(checksum) + 4(timestamp) + 8(flags) = 32 bytes
    hdr = f.read(32)
    sig = hdr[:4]
    if sig != b'MDMP':
        print("Not a minidump!")
        sys.exit(1)
    num_streams = struct.unpack_from('<I', hdr, 8)[0]
    stream_dir_rva = struct.unpack_from('<I', hdr, 12)[0]
    print(f"Streams: {num_streams}, Dir RVA: 0x{stream_dir_rva:x}")
    
    # Read stream directory
    f.seek(stream_dir_rva)
    streams = []
    for i in range(num_streams):
        st, ds, rva = struct.unpack_from('<III', f.read(12))
        streams.append((st, ds, rva))
    
    # Find ModuleListStream (type 4)
    for st, ds, rva in streams:
        if st == 4:
            print(f"\nModuleListStream at RVA 0x{rva:x}, size 0x{ds:x}")
            f.seek(rva)
            num_modules = struct.unpack_from('<I', f.read(4))[0]
            print(f"Modules: {num_modules}")
            for j in range(num_modules):
                # MINIDUMP_MODULE (108 bytes)
                # BaseOfImage(Q) SizeOfImage(I) CheckSum(I) TimeDateStamp(I) ModuleNameRva(I)
                # VsFixedFileInfo(52) CvRecord(8) MiscRecord(8) Reserved0(Q) Reserved1(Q)
                mod_data = f.read(108)
                base = struct.unpack_from('<Q', mod_data, 0)[0]
                size = struct.unpack_from('<I', mod_data, 8)[0]
                name_rva = struct.unpack_from('<I', mod_data, 16)[0]
                
                # Read name
                save = f.tell()
                f.seek(name_rva)
                name_len = struct.unpack_from('<I', f.read(4))[0]
                name = f.read(name_len).decode('utf-16-le', errors='replace')
                f.seek(save)
                
                if size > 0x100000 or 'axon' in name.lower() or 'AxonSkin' in name or 'DeskHelper' in name:
                    print(f"  [{j}] 0x{base:016x} size=0x{size:x} ({size/1048576:.1f}MB) {name}")
    
    # Also find Memory64ListStream (type 9) for raw memory ranges
    for st, ds, rva in streams:
        if st == 9:
            print(f"\nMemory64ListStream at RVA 0x{rva:x}")
            f.seek(rva)
            num_ranges = struct.unpack_from('<Q', f.read(8))[0]
            base_rva = struct.unpack_from('<Q', f.read(8))[0]
            print(f"  Ranges: {num_ranges}, Base RVA: 0x{base_rva:x}")
            cur_rva = base_rva
            large_ranges = []
            for j in range(num_ranges):
                start = struct.unpack_from('<Q', f.read(8))[0]
                size = struct.unpack_from('<Q', f.read(8))[0]
                if size > 0x100000:
                    large_ranges.append((start, size))
                    if len(large_ranges) <= 30:
                        print(f"  0x{start:016x} size=0x{size:x} ({size/1048576:.1f}MB)")
                cur_rva += size
            print(f"  ... {len(large_ranges)} ranges > 1MB")
