"""
Analyze the decrypted .rr4 stub code from the unpack/ dump.
The region r_00007ff7a27da000_00fc6000_p20 is the decrypted SProtect stub.
We:
 1) Save it as a raw .bin for IDA.
 2) Scan for anti-debug API resolution patterns.
    SProtect resolves APIs by PEB->Ldr hash. We look for:
      - access to PEB (mov rax, gs:[0x60] -> 65 48 8b 04 25 60 00 00 00)
      - Ldr walking (InLoadOrderModuleList at PEB+0x18)
      - hash comparison (cmp r32, imm32) -> these imm32 are API name hashes
    - IsDebuggerPresent/NtQueryInformationProcess calls via hash
 3) Find MessageBoxW-like: 4-arg calls (rcx,r8,r9,rdx setup) before call
 4) Report API hash constants (these identify which APIs).
"""
import os, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM, CS_OP_REG

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
SRC = os.path.join(OUT, "r_00007ff7a27da000_00fc6000_p20_t1000000.bin")
BASE = 0x7ff7a27da000

with open(SRC,"rb") as f: data=f.read()
print(f"stub region: 0x{BASE:x} {len(data)} bytes")

# save a copy for IDA with a synthetic PE header so IDA loads it as code
raw = os.path.join(OUT, "stub_rr4_mem.bin")
with open(raw,"wb") as f: f.write(data)
print(f"saved {raw}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# 1) PEB access: mov rax, gs:[0x60]
peb_pat = bytes([0x65,0x48,0x8b,0x04,0x25,0x60,0x00,0x00,0x00])
peb_hits = []
i = 0
while True:
    i = data.find(peb_pat, i)
    if i < 0: break
    peb_hits.append(BASE+i); i+=1
print(f"\nPEB access (gs:[0x60]) hits: {len(peb_hits)} at {[hex(x) for x in peb_hits[:10]]}")

# 2) Collect all cmp r32/r64, imm32/imm64 in the stub -> these include API hashes
# Disassemble whole region in chunks, collect CMP with imm operands and CALL targets
CHUNK=0x100000
cmps=[]      # (addr, imm, op_str)
calls=[]     # (addr, target or 0 if indirect)
movimm64=[]  # mov r64, imm64 (could be hash or string ptr)
total=0
for off in range(0,len(data),CHUNK):
    chunk=data[off:off+CHUNK]
    for ins in md.disasm(chunk, BASE+off):
        total+=1
        if ins.mnemonic=="cmp":
            for op in ins.operands:
                if op.type==CS_OP_IMM and op.imm>0x10000:
                    cmps.append((ins.address,op.imm,ins.op_str))
        if ins.mnemonic=="call":
            # direct e8 or indirect ff15/ff2x
            tgt=0
            if ins.operands and ins.operands[0].type==CS_OP_IMM:
                tgt=ins.operands[0].imm
            calls.append((ins.address,tgt,ins.op_str,ins.bytes.hex()))
        if ins.mnemonic=="mov" and len(ins.operands)==2:
            if ins.operands[1].type==CS_OP_IMM and ins.operands[1].imm>0x10000:
                movimm64.append((ins.address,ins.operands[1].imm,ins.op_str))

print(f"\ntotal insns disasmed: {total}")
print(f"cmp imm>0x10000: {len(cmps)}")
print(f"calls: {len(calls)}")
print(f"mov imm64>0x10000: {len(movimm64)}")

# 3) API hash candidates: cmp imm32 values that appear frequently
from collections import Counter
imm_cnt = Counter(c[1] for c in cmps)
print("\n=== top 30 CMP imm values (likely API name hashes) ===")
for imm,c in imm_cnt.most_common(30):
    # these are the hashes the stub compares resolved-api-hash against
    print(f"  0x{imm:x}  count={c}")

# 4) Direct call targets (resolved API wrappers)
direct = [(a,t,o,b) for (a,t,o,b) in calls if t!=0 and t>=BASE and t<BASE+len(data)]
print(f"\n=== direct call targets (within stub): {len(direct)} ===")
tlist = Counter(t for (_,t,_,_) in direct)
for tgt,c in tlist.most_common(20):
    print(f"  0x{tgt:x}  called {c}x")

# indirect calls (ff15 = call [rip+disp] -> IAT or resolved ptr)
indirect = [(a,t,o,b) for (a,t,o,b) in calls if t==0]
print(f"\n=== indirect calls: {len(indirect)} (sample 30) ===")
for (a,t,o,b) in indirect[:30]:
    print(f"  0x{a:x}  {b[:20]:20}  {o}")

# 5) Find the anti-debug dialog. The stub likely builds the "禁止调试" string or
#    stores it. Look for sequences that set up 4 args (rcx=0, rdx=title, r8=text, r9=0)
#    then call -> MessageBoxW pattern. Also MessageBoxW often preceded by push 0/MB flags.
# MessageBoxW args: hWnd=0, lpText, lpCaption, uType. So mov rcx,0; lea rdx,[text]; lea r8,[cap]; xor r9d,r9d or mov r9d,flag; call
# We look for 'xor r9d,r9d' (41 31 c9) or 'mov r9d,imm' near calls.
print("\n=== sequences: xor r9d,r9d (41 31 c9) - MessageBoxW arg4 setup ===")
r9z = data.find(bytes([0x41,0x31,0xc9]))
r9z_hits=[]
i=0
while True:
    i=data.find(bytes([0x41,0x31,0xc9]),i)
    if i<0: break
    r9z_hits.append(BASE+i); i+=1
print(f"xor r9d,r9d hits: {len(r9z_hits)}")

# save cmp hashes for IDA cross-ref
with open(os.path.join(OUT,"stub_cmp_hashes.txt"),"w") as f:
    for a,imm,o in cmps:
        f.write(f"0x{a:x}\t0x{imm:x}\t{o}\n")
with open(os.path.join(OUT,"stub_calls.txt"),"w") as f:
    for a,t,o,b in calls:
        f.write(f"0x{a:x}\ttgt=0x{t:x}\t{o}\t{b}\n")
print("\nsaved stub_cmp_hashes.txt, stub_calls.txt")
