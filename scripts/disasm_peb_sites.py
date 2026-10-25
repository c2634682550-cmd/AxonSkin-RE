"""Disassemble around the 3 PEB-access points and the xor r9d,r9d MessageBox site."""
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
SRC = os.path.join(OUT, "r_00007ff7a27da000_00fc6000_p20_t1000000.bin")
BASE = 0x7ff7a27da000
with open(SRC,"rb") as f: data=f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def disasm_at(va, length=0x300, label=""):
    off = va - BASE
    if off < 0 or off >= len(data): print(f"{label} 0x{va:x} out of range"); return
    chunk = data[off:off+length]
    print(f"\n=== {label} @ 0x{va:x} (off 0x{off:x}) ===")
    for ins in md.disasm(chunk, va):
        print(f"0x{ins.address:x}  {ins.bytes.hex()[:42]:42}  {ins.mnemonic} {ins.op_str}")

# PEB access points
for va in [0x7ff7a33765b7, 0x7ff7a3560ede, 0x7ff7a35696b0]:
    disasm_at(va, 0x200, "PEB access")

# xor r9d,r9d - find its actual address
pat = bytes([0x41,0x31,0xc9])
i = 0; r9z = []
while True:
    i = data.find(pat, i)
    if i<0: break
    r9z.append(BASE+i); i+=1
for va in r9z:
    disasm_at(va-0x80, 0x140, "xor r9d,r9d region")
