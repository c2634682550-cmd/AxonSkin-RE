"""Disassemble the SProtect stub entry: .rr4 first 0x10000 bytes, show all instructions and call targets."""
import struct, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
pe = pefile.PE(SRC, fast_load=True)
rr4 = next(s for s in pe.sections if s.Name.rstrip(b"\x00")==b".rr4")
with open(SRC,"rb") as f:
    f.seek(rr4.PointerToRawData)
    data = f.read(0x20000)  # first 128KB of .rr4 = stub

base_va = pe.OPTIONAL_HEADER.ImageBase + rr4.VirtualAddress
print(f".rr4 VA=0x{rr4.VirtualAddress:x} ImageBaseVA=0x{base_va:x}")
print(f"EP RVA=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x} -> in .rr4 at VA 0x{base_va + (pe.OPTIONAL_HEADER.AddressOfEntryPoint - rr4.VirtualAddress):x}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# EP is at .rr4 VA + (ep - rr4.VA). Let's disassemble starting at EP.
ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_off_in_rr4 = ep_rva - rr4.VirtualAddress
ep_va = base_va + ep_off_in_rr4
print(f"\n=== disasm from EP 0x{ep_va:x} (file off in .rr4 0x{ep_off_in_rr4:x}) ===")
# read from ep
chunk = data[ep_off_in_rr4:ep_off_in_rr4+0x8000]
lines = []
for ins in md.disasm(chunk, ep_va):
    lines.append((ins.address, ins.size, ins.mnemonic, ins.op_str, ins.bytes.hex()))
    if len(lines) > 2000: break

print(f"disassembled {len(lines)} instructions from EP")
# print first 200
for (addr, sz, mn, ops, hexs) in lines[:200]:
    print(f"0x{addr:x}  {hexs[:48]:48}  {mn} {ops}")

# find all calls/jmps
print("\n=== CALL/JMP instructions in first 0x8000 ===")
for (addr, sz, mn, ops, hexs) in lines:
    if mn in ("call","jmp") or mn.startswith("j"):
        print(f"0x{addr:x}  {mn} {ops}")

# also disassemble from very start of .rr4 (stub might begin before EP)
print(f"\n=== disasm from .rr4 start 0x{base_va:x} (first 0x1000) ===")
chunk0 = data[0:0x1000]
for ins in md.disasm(chunk0, base_va):
    print(f"0x{ins.address:x}  {ins.bytes.hex()[:48]:48}  {ins.mnemonic} {ins.op_str}")
