"""Use the minidump library to parse the full.dmp"""
import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'minidump'])
    from minidump.minidumpfile import MinidumpFile

md_path = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6\full.dmp"
mf = MinidumpFile.parse(md_path)

print("=== Modules ===")
if mf.modules:
    for m in mf.modules.modules:
        if m.sizeofimage > 0x100000 or 'axon' in (m.name or '').lower() or 'DeskHelper' in (m.name or ''):
            print(f"  0x{m.baseaddress:016x} size=0x{m.sizeofimage:x} ({m.sizeofimage/1048576:.1f}MB) {m.name}")

print("\n=== Memory regions (large) ===")
if mf.memory_segments_64:
    for seg in mf.memory_segments_64.memory_segments:
        if seg.end_memory_address - seg.start_memory_address > 0x100000:
            size = seg.end_memory_address - seg.start_memory_address
            print(f"  0x{seg.start_memory_address:016x} - 0x{seg.end_memory_address:016x} ({size/1048576:.1f}MB)")
elif mf.memory_segments:
    for seg in mf.memory_segments:
        if seg.end_memory_address - seg.start_memory_address > 0x100000:
            size = seg.end_memory_address - seg.start_memory_address
            print(f"  0x{seg.start_memory_address:016x} ({size/1048576:.1f}MB)")

# Extract the main module's .text from the minidump
print("\n=== Extracting main module ===")
if mf.modules:
    for m in mf.modules.modules:
        if m.name and ('AxonSkin' in m.name or 'DeskHelper' in m.name or 'axon' in m.name.lower()):
            print(f"Main module: 0x{m.baseaddress:016x} size=0x{m.sizeofimage:x} ({m.sizeofimage/1048576:.1f}MB) {m.name}")
            # The .text section starts at base + 0x1000
            # SizeOfImage covers all sections
            break

# Try to read the .text section from minidump
import struct
# Read the main module memory from minidump
# Use the reader to get memory at specific addresses
reader = mf.get_reader()
# The main module base (from module list)
main_base = None
for m in mf.modules.modules:
    if m.name and ('AxonSkin' in m.name or 'DeskHelper' in m.name or 'axon' in m.name.lower()):
        main_base = m.baseaddress
        main_size = m.sizeofimage
        break

if main_base:
    print(f"\n=== Reading main module memory at 0x{main_base:x} ===")
    try:
        # Read first 0x1000 bytes (headers)
        hdr = reader.read(main_base, 0x1000)
        if hdr[:2] == b'MZ':
            print("  MZ header found!")
            e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
            print(f"  e_lfanew = 0x{e_lfanew:x}")
            # Read PE header
            pe_hdr = reader.read(main_base + e_lfanew, 0x400)
            if pe_hdr[:4] == b'PE\x00\x00':
                print("  PE signature found!")
                num_sections = struct.unpack_from('<H', pe_hdr, 6)[0]
                opt_hdr_size = struct.unpack_from('<H', pe_hdr, 20)[0]
                print(f"  Sections: {num_sections}, OptHdrSize: 0x{opt_hdr_size:x}")
                # Section table starts at e_lfanew + 24 + opt_hdr_size
                sec_offset = 24 + opt_hdr_size
                for i in range(num_sections):
                    s = pe_hdr[sec_offset + i*40:sec_offset + (i+1)*40]
                    if len(s) >= 40:
                        name = s[:8].rstrip(b'\x00').decode('ascii','replace')
                        vsize = struct.unpack_from('<I', s, 8)[0]
                        va = struct.unpack_from('<I', s, 12)[0]
                        rawsize = struct.unpack_from('<I', s, 16)[0]
                        print(f"  Section {name:12} VA=0x{va:x} VSize=0x{vsize:x} RawSize=0x{rawsize:x}")
                        
                        # If this is .text, read it
                        if name == '.text' and vsize > 0:
                            print(f"  -> Reading .text ({vsize/1048576:.1f}MB)...")
                            try:
                                text_data = reader.read(main_base + va, min(vsize, 0x4000000))
                                # Check if it contains real code
                                prologues = text_data[:0x100000].count(b'\x48\x89\x5c\x24')
                                print(f"  -> Read {len(text_data)/1048576:.1f}MB, prologues in 1st MB: {prologues}")
                                # Save to file
                                out_path = os.path.join(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6", "main_text_decrypted.bin")
                                with open(out_path, "wb") as f:
                                    f.write(text_data)
                                print(f"  -> Saved to {out_path}")
                            except Exception as e:
                                print(f"  -> Read failed: {e}")
    except Exception as e:
        print(f"  Error: {e}")
else:
    print("Main module not found in module list")
    print("All modules:")
    for m in mf.modules.modules:
        print(f"  0x{m.baseaddress:016x} {m.name}")
