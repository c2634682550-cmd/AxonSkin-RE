"""Check if the dumped EXECUTE regions contain the decrypted .text section.
The .text section should be 38MB, start with Qt6 platform plugin code or main module code."""
import os, sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6"

# Check the 30MB EXECUTE region first
big_file = os.path.join(OUT_DIR, "r_00007ff7925db000_01dfd000_p20_t1000000.bin")
if os.path.exists(big_file):
    size = os.path.getsize(big_file)
    print(f"=== 30MB EXECUTE region: {size/1048576:.1f}MB ===")
    with open(big_file, "rb") as f:
        # Read first 256 bytes
        head = f.read(256)
        print(f"First 64 bytes hex: {head[:64].hex()}")
        # Check for MZ header
        if head[:2] == b'MZ':
            print("  -> Starts with MZ header!")
        # Check for common patterns
        if b'\x48\x89' in head[:32] or b'\x48\x8b' in head[:32]:
            print("  -> Contains x64 function prologues (mov rsp/rbp)")
        
        # Scan for function prologues (48 89 5C 24 = mov [rsp+x], rbx)
        f.seek(0)
        data = f.read(min(size, 0x100000))  # First 1MB
        prologue_count = data.count(b'\x48\x89\x5c\x24')
        print(f"  Function prologues in first 1MB: {prologue_count}")
        
        # Look for Qt strings
        qt_strings = [b'Qt6Core', b'Qt6Gui', b'Qt6Widgets', b'Qt6Network', b'QApplication', b'QObject', b'QWidget', b'QMainWindow', b'AxonSkin', b'DeskHelper']
        for s in qt_strings:
            pos = data.find(s)
            if pos >= 0:
                print(f"  Found '{s.decode()}' at offset 0x{pos:x}")
        
        # Check if this is the main module's .text
        # Main module base was 0x7ff7925db000 - this matches!
        # .text starts at RVA 0x1000
        # So if base=0x7ff7925db000 and .text RVA=0x1000, .text would be at 0x7ff7925dc000
        print(f"  Region base: 0x7ff7925db000")
        print(f"  If this is main module, .text at base+0x1000 = 0x7ff7925dc000")

# Check the 15.8MB region
big_file2 = os.path.join(OUT_DIR, "r_00007ff7a27da000_00fc6000_p20_t1000000.bin")
if os.path.exists(big_file2):
    size = os.path.getsize(big_file2)
    print(f"\n=== 15.8MB EXECUTE region: {size/1048576:.1f}MB ===")
    with open(big_file2, "rb") as f:
        head = f.read(256)
        print(f"First 64 bytes hex: {head[:64].hex()}")
        f.seek(0)
        data = f.read(min(size, 0x100000))
        prologue_count = data.count(b'\x48\x89\x5c\x24')
        print(f"  Function prologues in first 1MB: {prologue_count}")
        qt_strings = [b'Qt6Core', b'Qt6Gui', b'Qt6Widgets', b'AxonSkin', b'DeskHelper', b'QApplication', b'boost', b'asio']
        for s in qt_strings:
            pos = data.find(s)
            if pos >= 0:
                print(f"  Found '{s.decode()}' at offset 0x{pos:x}")

# Also check the minidump
md_file = os.path.join(OUT_DIR, "full.dmp")
if os.path.exists(md_file):
    md_size = os.path.getsize(md_file)
    print(f"\n=== Minidump: {md_size/1048576:.1f}MB ===")
    # Check minidump header
    with open(md_file, "rb") as f:
        sig = f.read(4)
        print(f"  Signature: {sig.hex()} ({'MDMP' if sig == b'MDMP' else 'UNKNOWN'})")

# List all files in unpack6
print(f"\n=== All files in unpack6 ===")
for f in sorted(os.listdir(OUT_DIR)):
    fpath = os.path.join(OUT_DIR, f)
    if os.path.isfile(fpath):
        print(f"  {f}: {os.path.getsize(fpath)/1048576:.1f}MB")
