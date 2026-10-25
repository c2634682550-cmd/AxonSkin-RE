"""Build a reconstructed PE from the decrypted .a1 code region.
The code is at .a1 + 0x1000000, which in the module is at RVA 0x4fdb000.
We'll create a simple PE-like file that IDA can load as a raw binary at the correct VA.
"""
import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"

# Read the decrypted code
code_path = os.path.join(WORK, "a1_code_live.bin")
with open(code_path, "rb") as f:
    code_data = f.read()

print(f"Code region: {len(code_data)/1048576:.1f}MB")

# The code is at VA 0x7ff7925db000 + 0x1000000 = 0x7ff7935db000
# In the module, .a1 starts at RVA 0x3edb000
# So code is at RVA 0x3edb000 + 0x1000000 = 0x4fdb000
# Module base = 0x7ff78e700000
# Code VA = 0x7ff78e700000 + 0x4fdb000 = 0x7ff7936db000

# Wait, let me recalculate:
# .a1 VA = 0x3edb000 (section VA)
# .a1 is at module_base + 0x3edb000 = 0x7ff78e700000 + 0x3edb000 = 0x7ff7925db000
# The dump file r_00007ff7925db000 starts at 0x7ff7925db000 = .a1 start
# Code starts at offset 0x1000000 within .a1
# So code VA = 0x7ff7925db000 + 0x1000000 = 0x7ff7935db000
# Code RVA = 0x3edb000 + 0x1000000 = 0x4fdb000

code_va = 0x7ff7935db000
code_rva = 0x4fdb000
code_size = len(code_data)

print(f"Code VA: 0x{code_va:x}")
print(f"Code RVA: 0x{code_rva:x}")
print(f"Code size: 0x{code_size:x} ({code_size/1048576:.1f}MB)")

# Also extract .rdata - but it's all zeros from the dump
# The .rdata might be in the .a1 region too, or in .pkg/.rr4
# Let's check .pkg (VA=0x5cd9000, VSize=113MB) and .rr4 (VA=0xce1f000, VSize=130MB)

# For now, let's also look for strings within the code region
import re
# ASCII strings in code region
ascii_strings = re.findall(rb'[\x20-\x7e]{12,}', code_data)
print(f"\nASCII strings in code region: {len(ascii_strings)}")
# Show interesting ones
interesting = [s for s in ascii_strings if any(kw in s for kw in [b'Qt', b'Axon', b'skin', b'Skin', b'boost', b'asio', b'http', b'Dlg_', b'QWidget', b'QMain', b'config', b'cache', b'license', b'auth', b'login'])]
print(f"Interesting strings: {len(interesting)}")
for s in interesting[:30]:
    print(f"  {s.decode('ascii','replace')[:120]}")

# UTF-16LE strings in code region
print(f"\nUTF-16LE strings in code region:")
utf16 = []
i = 0
while i < len(code_data) - 4:
    if code_data[i+1] == 0 and 0x20 <= code_data[i] <= 0x7e:
        j = i
        chars = []
        while j < len(code_data) - 1:
            lo = code_data[j]
            hi = code_data[j+1]
            if hi == 0 and 0x20 <= lo <= 0x7e:
                chars.append(chr(lo))
                j += 2
            elif hi > 0:
                # Could be CJK
                code_point = lo | (hi << 8)
                if code_point >= 0x4e00:  # CJK
                    chars.append(chr(code_point))
                    j += 2
                else:
                    break
            else:
                break
        if len(chars) >= 8:
            s = ''.join(chars)
            utf16.append((i, s))
        i = j + 2
    else:
        i += 1

print(f"Found {len(utf16)} UTF-16LE strings")
for off, s in utf16[:40]:
    if len(s.strip()) >= 6:
        print(f"  0x{off:08x}: {s[:120]}")

# Create a PE file for IDA
# We'll create a minimal PE with the code at the right RVA
print(f"\n=== Creating reconstructed PE ===")
out_pe = os.path.join(WORK, "AxonSkin_decrypted_text.bin")

# For IDA, just save as raw binary - we'll load it with the correct base address
with open(out_pe, "wb") as f:
    f.write(code_data)

print(f"Saved raw binary: {out_pe} ({os.path.getsize(out_pe)/1048576:.1f}MB)")
print(f"Load in IDA as: raw binary, base address 0x{code_va:x}, processor x86-64")
