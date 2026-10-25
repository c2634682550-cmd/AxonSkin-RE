"""Find Dlg_Login, VirtualProtect, IsDebuggerPresent references in axon_inner.bin.
Also search .rdata for class vtable names."""
import pefile, re, struct

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axon_inner.bin")
data = open(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axon_inner.bin","rb").read()

# Extract all ASCII strings with their RVA
print("=== Class/method strings (RTTI) ===")
for s in re.finditer(rb"[\x20-\x7e]{8,}", data):
    txt = s.group().decode('ascii','replace')
    if any(k in txt for k in ['Dlg_','Virtual','Debug','Protect','Login','Init','Main','Entry','Start','Decrypt','Xor','Crypt','SProtect','SP_','Online','Client','Bind','Trial','Auth','Key','Verify','Check','Config','Cloud','Server','Network','Socket','Connect','Send','Recv','asio','boost','QMain','Widget','Skin','Axon','Desk','Helper']):
        file_off = s.start()
        # find which section
        rva = pe.get_rva_from_offset(file_off) if file_off < pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData else 0
        print(f"  off=0x{file_off:x} rva=0x{rva:x} {txt}")

# Find VirtualProtect import
print("\n=== Import table ===")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for m in pe.DIRECTORY_ENTRY_IMPORT:
        for i in m.imports:
            nm = i.name.decode() if i.name else f"#{i.ordinal}"
            if any(k in nm for k in ['Virtual','Debug','Protect','Crypt','Create','Write','Read','Load','GetProc','Module','File','Heap','Alloc','Free','Thread','Process']):
                print(f"  {m.dll.decode()}: {nm} @ IAT 0x{i.address:x}")

# Find exports
print("\n=== Exports ===")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(f"  {e.name.decode() if e.name else '#'+str(e.ordinal)} @ RVA 0x{e.address:x}")

# Find .text section and look for VirtualProtect call pattern (FF15 = call [rip+disp])
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tdata = text.get_data()
print(f"\n=== .text: VA=0x{text.VirtualAddress:x} size=0x{text.Misc_VirtualSize:x} ===")

# find IAT address for VirtualProtect
iat_addrs = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for m in pe.DIRECTORY_ENTRY_IMPORT:
        for i in m.imports:
            nm = i.name.decode() if i.name else f"#{i.ordinal}"
            iat_addrs[i.address] = nm

# search for call [rip+disp] instructions that target VirtualProtect in IAT
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
base = pe.OPTIONAL_HEADER.ImageBase

print("\n=== Calls to VirtualProtect/IsDebuggerPresent ===")
count = 0
for ins in md.disasm(tdata, base + text.VirtualAddress):
    if ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == 2:  # CS_OP_MEM
        # call [rip+disp] -> compute target
        op = ins.operands[0]
        # target = rip + disp = ins.address + ins.size + disp
        if hasattr(op, 'mem') and op.mem.base == 0:  # rip-relative
            disp = op.mem.disp
            target = ins.address + ins.size + disp
            if target in iat_addrs:
                nm = iat_addrs[target]
                if 'Virtual' in nm or 'Debug' in nm or 'Protect' in nm:
                    print(f"  0x{ins.address:x} call [{nm}]")
                    count += 1
                    if count > 30: break

# Also find mov gs:[0x60] (PEB access) and int 2e (syscall)
print("\n=== PEB access / anti-debug patterns ===")
peb_hits = 0
for i in range(len(tdata)-9):
    if tdata[i:i+5] == bytes([0x65,0x48,0x8b,0x04,0x25]):  # mov rax,gs:[imm32]
        peb_hits += 1
        if peb_hits <= 5:
            print(f"  PEB access at 0x{base+text.VirtualAddress+i:x}")
    if tdata[i:i+2] == bytes([0x0f,0x31]):  # rdtsc
        if peb_hits <= 10:
            print(f"  rdtsc at 0x{base+text.VirtualAddress+i:x}")
print(f"  total PEB access: {peb_hits}")
