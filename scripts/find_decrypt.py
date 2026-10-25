"""Find and disassemble sub_180005890 in axonlogin.dll to understand string decryption."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll")
base = pe.OPTIONAL_HEADER.ImageBase  # 0x180000000

# sub_180005890 is at RVA 0x5890
rva = 0x5890
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
text_data = text.get_data()
text_va = base + text.VirtualAddress

# offset into text_data
off = rva - text.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"=== sub_180005890 @ RVA 0x{rva:x} (file offset 0x{text.PointerToRawData + off:x}) ===")
# disassemble 256 bytes
code = text_data[off:off+256]
for ins in md.disasm(code, base + rva):
    print(f"  0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str}")
    if ins.mnemonic == 'ret' or (ins.mnemonic == 'jmp' and not ins.op_str.startswith('0x')):
        # check if it's a simple ret/jmp that ends the function
        if ins.mnemonic == 'ret':
            break
    if ins.address > base + rva + 200:
        break

# Also look at the encrypted string "S_MR\rN/f" at the call site
# and unk_180038B30
print(f"\n=== unk_180038B30 (RVA 0x38B30) ===")
rdata = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.rdata')
rdata_data = rdata.get_data()
rdata_off = 0x38B30 - rdata.VirtualAddress
if 0 <= rdata_off < len(rdata_data):
    data = rdata_data[rdata_off:rdata_off+128]
    print(f"  hex: {data.hex()}")
    print(f"  ascii: {data.decode('ascii','replace')}")
else:
    print(f"  offset out of range: {rdata_off}")

# Try to decrypt "S_MR\rN/f" with various XOR keys
enc = b"S_MR\rN/f"
print(f"\n=== XOR decrypt attempts for 'S_MR\\rN/f' ===")
for key in range(256):
    dec = bytes(b ^ key for b in enc)
    if all(32 <= b <= 126 for b in dec):
        print(f"  XOR 0x{key:02x}: {dec.decode('ascii')}")

# Also try XOR with unk_180038B30 data as key
if 0 <= rdata_off < len(rdata_data):
    key_data = rdata_data[rdata_off:rdata_off+8]
    dec = bytes(a ^ b for a, b in zip(enc, key_data))
    if all(32 <= b <= 126 for b in dec):
        print(f"  XOR with unk key: {dec.decode('ascii')}")
    else:
        print(f"  XOR with unk key (raw): {dec}")
