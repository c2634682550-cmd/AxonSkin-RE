"""Deep analysis of the .text dump - check actual byte content."""
import sys, os, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"

# Check .text content
text_path = os.path.join(OUT, "main_text.bin")
with open(text_path, "rb") as f:
    data = f.read()

print(f"=== .text content analysis ({len(data)/1048576:.1f}MB) ===")

# Check entropy/byte distribution
from collections import Counter
c = Counter(data[:0x100000])
print(f"First 1MB byte distribution (top 20):")
for byte, count in c.most_common(20):
    print(f"  0x{byte:02x}: {count} ({count/0x100000*100:.1f}%)")

# Check if all zeros
zeros = data.count(b'\x00')
print(f"\nTotal zeros: {zeros} ({zeros/len(data)*100:.1f}%)")
nonzeros = len(data) - zeros
print(f"Total non-zeros: {nonzeros} ({nonzeros/len(data)*100:.1f}%)")

# First 256 bytes
print(f"\nFirst 256 bytes:")
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
    print(f"  {i:04x}: {hex_part}  {ascii_part}")

# Check at various offsets
print(f"\nBytes at various offsets:")
for offset in [0x1000, 0x10000, 0x100000, 0x500000, 0x1000000, 0x1500000, 0x2000000, 0x2500000]:
    if offset < len(data):
        chunk = data[offset:offset+32]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  0x{offset:08x}: {hex_part}")

# Check .rdata content
rdata_path = os.path.join(OUT, "main_rdata.bin")
with open(rdata_path, "rb") as f:
    rdata = f.read()

print(f"\n=== .rdata content analysis ({len(rdata)/1048576:.1f}MB) ===")
c2 = Counter(rdata[:0x100000])
print(f"First 1MB byte distribution (top 10):")
for byte, count in c2.most_common(10):
    print(f"  0x{byte:02x}: {count} ({count/0x100000*100:.1f}%)")

zeros2 = rdata.count(b'\x00')
print(f"Total zeros: {zeros2} ({zeros2/len(rdata)*100:.1f}%)")

print(f"\nFirst 256 bytes of .rdata:")
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02x}' for b in rdata[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in rdata[i:i+16])
    print(f"  {i:04x}: {hex_part}  {ascii_part}")

# Check if .text might be in a different memory region
# The 30MB EXECUTE region we found earlier at 0x7ff7925db000 is actually .a1 section
# .a1 VA=0x3edb000 VSize=0x1dfd000 (30MB) with RawSize on disk
# So 0x7ff78e700000 + 0x3edb000 = 0x7ff7925db000 — that's .a1, not .text!
# .a1 contains the SProtect stub code

# The .text section (VA=0x1000, VSize=38MB) is at 0x7ff78e701000
# But it's still zero/encrypted

# Let me check if the process actually decrypted .text
# Maybe SProtect maps .text to a different address?
# Or maybe the process hasn't actually logged in

# Check the process window
import ctypes
user32 = ctypes.WinDLL("user32")
EnumWindows = user32.EnumWindows
GetWindowTextW = user32.GetWindowTextW
GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
IsWindowVisible = user32.IsWindowVisible
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]

WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

windows = []
def callback(hwnd, lparam):
    title = ctypes.create_unicode_buffer(256)
    GetWindowTextW(hwnd, title, 256)
    pid = ctypes.c_uint(0)
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if IsWindowVisible(hwnd) and title.value:
        windows.append((pid.value, hwnd, title.value))
    return True

EnumWindows(WNDENUMPROC(callback), 0)
print("\n=== Windows for PID 54824 ===")
for pid, hwnd, title in windows:
    if pid == 54824:
        print(f"  HWND={hwnd} title='{title}'")
