"""Analyze cloud-cfg.bin - may contain server config, encrypted with XOR."""
import os

path = r"C:\Users\26346\AppData\Roaming\Axon\AxonSkin\cache\cloud-cfg.bin"
data = open(path,"rb").read()
print(f"size: {len(data)}")
print(f"hex: {data.hex()}")
print(f"raw: {data}")

# Try XOR with common keys
for key in [0x2f, 0xff, 0xa5, 0x5a, 0x37, 0x42]:
    decoded = bytes(b ^ key for b in data)
    printable = ''.join(chr(b) if 32<=b<=126 else '.' for b in decoded)
    if any(c.isalpha() for c in printable):
        print(f"XOR 0x{key:02x}: {printable}")

# Try as JSON (might be partially readable)
try:
    txt = data.decode('utf-8','replace')
    print(f"UTF-8: {txt}")
except: pass
try:
    txt = data.decode('utf-16-le','replace')
    print(f"UTF-16: {txt}")
except: pass
