"""Scan the full 38MB .text dump for code patterns and real function prologues.
Also scan .rdata for strings (including UTF-16LE)."""
import sys, os, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6"

# Scan .text
text_path = os.path.join(OUT, "main_text_decrypted.bin")
with open(text_path, "rb") as f:
    text_data = f.read()

print(f"=== .text scan ({len(text_data)/1048576:.1f}MB) ===")
# Scan every 256KB
for i in range(0, len(text_data), 0x40000):
    chunk = text_data[i:i+0x40000]
    if len(chunk) < 0x1000:
        break
    prologues = chunk.count(b'\x48\x89\x5c\x24')
    calls = chunk.count(b'\xe8') + chunk.count(b'\xff\x15')
    zeros = chunk.count(b'\x00')
    nonzero_ratio = 1 - zeros / len(chunk) if len(chunk) > 0 else 0
    if prologues > 5 or (calls > 100 and nonzero_ratio > 0.5):
        print(f"  0x{i:08x} ({i//1048576:2d}MB): prol={prologues:4d} calls={calls:5d} nonzero={nonzero_ratio:.0%}")

# Scan .rdata for strings
rdata_path = os.path.join(OUT, "main_rdata_decrypted.bin")
with open(rdata_path, "rb") as f:
    rdata_data = f.read()

print(f"\n=== .rdata scan ({len(rdata_data)/1048576:.1f}MB) ===")
# ASCII strings
ascii_strings = re.findall(rb'[\x20-\x7e]{12,}', rdata_data[:0x200000])
print(f"ASCII strings in first 2MB: {len(ascii_strings)}")
for s in ascii_strings[:30]:
    print(f"  {s.decode('ascii','replace')[:100]}")

# UTF-16LE strings
print(f"\nUTF-16LE strings:")
utf16_strings = []
i = 0
while i < len(rdata_data) - 4:
    # Look for sequences of printable UTF-16LE chars
    if rdata_data[i+1] == 0 and 0x20 <= rdata_data[i] <= 0x7e:
        s = bytearray()
        j = i
        while j < len(rdata_data) - 1:
            lo = rdata_data[j]
            hi = rdata_data[j+1]
            if hi == 0 and 0x20 <= lo <= 0x7e:
                s.append(lo)
                j += 2
            elif hi > 0:  # CJK or extended
                s.extend(rdata_data[j:j+2])
                j += 2
            else:
                break
        if len(s) >= 12:
            try:
                decoded = bytes(s).decode('utf-16-le' if any(s[k] > 0x7f for k in range(len(s))) else 'ascii', errors='replace')
                # Re-decode properly
                raw = rdata_data[i:j]
                decoded = raw.decode('utf-16-le', errors='replace')
                if len(decoded.strip()) >= 6:
                    utf16_strings.append((i, decoded.strip()))
            except:
                pass
        i = j + 2
    else:
        i += 1

print(f"Found {len(utf16_strings)} UTF-16LE strings (first 30):")
for off, s in utf16_strings[:30]:
    print(f"  0x{off:08x}: {s[:100]}")
