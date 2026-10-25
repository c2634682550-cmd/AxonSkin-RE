"""Decrypt XOR-encrypted strings in axonlogin.dll .rdata section.
The encrypted strings use a simple XOR with a repeating key.
unk_180038B30 contains the encrypted data."""
import pefile, sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll")
base = pe.OPTIONAL_HEADER.ImageBase

rdata = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.rdata')
rdata_data = rdata.get_data()
rdata_va = base + rdata.VirtualAddress

# The data at 0x38B30 contains encrypted strings
# Let's dump a larger region and try to find the XOR key
off = 0x38B30 - rdata.VirtualAddress
region = rdata_data[off:off+512]
print(f"=== unk_180038B30 region ({len(region)} bytes) ===")
print(f"hex: {region.hex()}")

# The string "S_MR\rN/f" is at offset 0x18 in this region
# Known plaintext: if this is a MessageBox title, it might be "错误" or "提示" or "警告"
# Let's try common XOR keys

# Actually, looking at the hex more carefully:
# 48722c67f466b065 00000000 00000000
# 535f4d520d4e2f66 00 67b06548722c67 0cffb970fb515b00 6e789a5b5d004d5280 5f0b4e7d8f00 67b06548722c6701ff 00000000 00000000
# 8179626b7b764696 00000000...
# b783d6536c514a543159258d02302800f78b6e78dd4fcd645c4ffb7cdf7e005f

# The pattern "67b06548722c67" appears twice - this is likely a repeated encrypted string
# with the same XOR key

# Let's try: if the plaintext is Chinese (UTF-16LE), the key might be multi-byte
# "S_MR\rN/f" has 8 bytes. If this XORs to "提示信息" (4 Chinese chars = 8 bytes UTF-16LE):
# 提 = 0x63D0, 示 = 0x3A79, 信 = 0x21E4, 息 = 0x1F60
# But we don't know the plaintext yet.

# Let's try a different approach: look for the XOR key by analyzing the zero-padded areas
# In the hex: 48722c67f466b065 00000000 00000000 535f4d520d4e2f6600
# The zeros after the first 8 bytes suggest the string is 8 bytes long
# If we XOR with a key, the zeros would reveal the key
# 00000000 00000000 → key bytes at those positions

# Actually, let's look at the structure differently
# The call was: sub_180005890(a1 + 8, "S_MR\rN/f", &unk_180038B30, 64)
# Parameters: (dest, encrypted_str, key_table, length=64)
# So unk_180038B30 is a 64-byte key table!

key_table = rdata_data[off:off+64]
print(f"\n=== Key table (64 bytes) ===")
print(f"hex: {key_table.hex()}")

# The encrypted string "S_MR\rN/f" is 8 bytes
enc_str = b"S_MR\rN/f"
print(f"\n=== Decrypting 'S_MR\\rN/f' with key table ===")
# XOR first 8 bytes of enc_str with first 8 bytes of key_table
for i in range(64):
    key_byte = key_table[i % 64]
    if i < len(enc_str):
        dec = enc_str[i] ^ key_byte
        print(f"  [{i}] enc=0x{enc_str[i]:02x} key=0x{key_byte:02x} dec=0x{dec:02x} chr={chr(dec) if 32<=dec<=126 else '?'}")

# The key table starts with 48722c67f466b065
# XOR S_MR with 48722c67: 
# S(0x53) ^ 0x48 = 0x1B (ESC - not printable)
# This doesn't produce printable ASCII

# Maybe the key is applied differently - maybe the string is the key and unk is the data?
print(f"\n=== Alternative: 'S_MR\\rN/f' as key, unk as data ===")
for i in range(min(32, len(key_table))):
    dec = key_table[i] ^ enc_str[i % len(enc_str)]
    if 32 <= dec <= 126 or dec == 0:
        print(f"  [{i}] data=0x{key_table[i]:02x} key=0x{enc_str[i%8]:02x} dec=0x{dec:02x} chr={chr(dec) if dec else 'NULL'}")

# Try: maybe the 4th parameter (64) is not key length but something else
# and the decryption uses a simple single-byte XOR
print(f"\n=== Single byte XOR on entire .rdata region ===")
# Search for patterns that look like UTF-16LE Chinese text after XOR
for key in range(256):
    decrypted = bytes(b ^ key for b in rdata_data[off:off+256])
    # Check for UTF-16LE Chinese text (common range 0x4E00-0x9FFF)
    try:
        text = decrypted.decode('utf-16-le', errors='strict')
        if any('\u4e00' <= c <= '\u9fff' for c in text[:20]):
            print(f"  XOR 0x{key:02x}: {text[:40]}")
    except:
        pass
    # Also check for ASCII
    ascii_text = decrypted.decode('ascii', errors='replace')
    if sum(1 for c in ascii_text[:20] if c.isalpha()) > 10:
        print(f"  XOR 0x{key:02x} (ascii): {ascii_text[:40]}")

# Also extract all NULL-terminated UTF-16LE strings from .rdata
print(f"\n=== All UTF-16LE strings in .rdata ===")
strings = []
i = 0
while i < len(rdata_data) - 3:
    if rdata_data[i] != 0 and rdata_data[i+1] == 0:
        # potential UTF-16LE string
        end = i
        while end < len(rdata_data) - 1:
            if rdata_data[end] == 0 and rdata_data[end+1] == 0:
                break
            end += 2
        if end - i >= 4:  # at least 2 chars
            try:
                s = rdata_data[i:end].decode('utf-16-le', errors='replace')
                if len(s) >= 2 and any(c.isprintable() for c in s):
                    rva = rdata.VirtualAddress + i
                    strings.append((rva, s))
            except:
                pass
        i = end + 2
    else:
        i += 2

for rva, s in strings[:50]:
    print(f"  0x{base+rva:x}: {s}")
print(f"  ... ({len(strings)} total)")
