"""Disassemble exactly at EP within .rr4 on-disk."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
pe = pefile.PE(SRC, fast_load=True)
rr4 = next(s for s in pe.sections if s.Name.rstrip(b"\x00")==b".rr4")
ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_off_in_rr4 = ep_rva - rr4.VirtualAddress   # offset within .rr4's data
ep_file_off = rr4.PointerToRawData + ep_off_in_rr4
base_va = pe.OPTIONAL_HEADER.ImageBase + ep_rva

print(f"EP RVA=0x{ep_rva:x}  .rr4 VA=0x{rr4.VirtualAddress:x}  off_in_rr4=0x{ep_off_in_rr4:x}")
print(f"EP file offset=0x{ep_file_off:x}  EP VA=0x{base_va:x}")
print(f".rr4 RawSize=0x{rr4.SizeOfRawData:x}  ep_off_in_rr4=0x{ep_off_in_rr4:x} (in range: {ep_off_in_rr4 < rr4.SizeOfRawData})")

with open(SRC,"rb") as f:
    f.seek(ep_file_off)
    data = f.read(0x4000)   # 16KB starting at EP

print(f"\nfirst 64 bytes at EP: {data[:64].hex(' ')}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
lines = list(md.disasm(data, base_va))
print(f"\ndisassembled {len(lines)} instructions from EP")
print("=== first 250 instructions ===")
for ins in lines[:250]:
    print(f"0x{ins.address:x}  {ins.bytes.hex()[:40]:40}  {ins.mnemonic} {ins.op_str}")

print("\n=== calls/jmps ===")
for ins in lines:
    if ins.mnemonic in ("call","jmp") or ins.mnemonic.startswith("j"):
        print(f"0x{ins.address:x}  {ins.mnemonic} {ins.op_str}")
