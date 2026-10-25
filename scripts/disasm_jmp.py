"""Follow the EP jmp chain and disassemble the real SProtect stub body."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
pe = pefile.PE(SRC, fast_load=True)
rr4 = next(s for s in pe.sections if s.Name.rstrip(b"\x00")==b".rr4")
ib = pe.OPTIONAL_HEADER.ImageBase

# jmp target from EP: 0x154e9f1e6
target_va = 0x154e9f1e6
# which section?
def sec_for_va(va):
    rva = va - ib
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None

s = sec_for_va(target_va)
snm = s.Name.rstrip(b"\x00").decode("latin1","replace")
print(f"jmp target 0x{target_va:x} -> section {snm}")
off_in_sec = target_va - ib - s.VirtualAddress
file_off = s.PointerToRawData + off_in_sec
print(f"  off_in_sec=0x{off_in_sec:x} file_off=0x{file_off:x} (sec RawSize=0x{s.SizeOfRawData:x}, in range: {off_in_sec < s.SizeOfRawData})")

with open(SRC,"rb") as f:
    f.seek(file_off)
    data = f.read(0x8000)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
lines = list(md.disasm(data, target_va))
print(f"\ndisassembled {len(lines)} instructions from 0x{target_va:x}")
print("=== first 300 ===")
for ins in lines[:300]:
    print(f"0x{ins.address:x}  {ins.bytes.hex()[:42]:42}  {ins.mnemonic} {ins.op_str}")

print("\n=== calls/jmps ===")
for ins in lines:
    if ins.mnemonic in ("call","jmp") or ins.mnemonic.startswith("j"):
        print(f"0x{ins.address:x}  {ins.mnemonic} {ins.op_str}")
