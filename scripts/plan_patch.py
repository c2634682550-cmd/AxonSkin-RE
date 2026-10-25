"""Get raw bytes of sub_1800091D0 and sub_180006560 to plan patches.
sub_1800091D0 (RVA 0x91D0): online auth - patch to always succeed
sub_180006560 (RVA 0x6560): login button - patch card key validation to return 1"""
import pefile, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
text_data = text.get_data()
text_raw = text.PointerToRawData
text_va = base + text.VirtualAddress

md = Cs(CS_ARCH_X86, CS_MODE_64)

def disasm_func(rva, size, label):
    off = rva - text.VirtualAddress
    code = text_data[off:off+size]
    print(f"\n{'='*60}")
    print(f"{label} @ RVA 0x{rva:x} (file offset 0x{text_raw+off:x})")
    print(f"{'='*60}")
    for ins in md.disasm(code, base + rva):
        raw = code[ins.address - (base+rva):ins.address - (base+rva) + ins.size]
        print(f"  0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str:30s}  ; {raw.hex()}")

# sub_1800091D0 - size 0x111
disasm_func(0x91D0, 0x111, "sub_1800091D0 (online auth)")

# sub_180006560 - size 0x950 - just the first 256 bytes (the card key call site)
disasm_func(0x6560, 0x200, "sub_180006560 (login button - first 512B)")

# Also find the exact offset of the call to qword_180050B80 in sub_180006560
# The call is at line 4508: v16 = (*qword_180050B80)(v15, v38)
# This is: call qword ptr [rip + offset_to_qword_180050B80]
# qword_180050B80 is at RVA 0x50B80
print(f"\nqword_180050B80 at RVA 0x50B80")
