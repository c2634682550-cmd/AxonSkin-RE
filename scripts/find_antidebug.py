"""
Locate the anti-debug string "禁止调试软件..." and find code references to it.
- The string lives in a PRIVATE RWX region (base 0x2a09d9e0000) and/or the MAPPED region.
- Code that references it is in the EXECUTE region(s). We search the .rr4 exec region
  for lea/mov instructions whose displacement or RIP-relative target equals the string VA.
- But ASLR means the string VA differs per run. We recorded runtime bases in manifest.
Strategy:
  1) For each region, record (region_base, file_path, prot).
  2) Build a global address->region map.
  3) Find the exact offset of "禁止调试软件" (UTF-16) in each region file -> VA.
  4) Scan the EXECUTE region(s) bytes for RIP-relative LEA referencing those VAs.
     x64 LEA r64, [rip+disp32] = 48 8d xx (xx=05..3f for rax..rdi, 4c for r8-r15 etc) then disp32.
     Also MOV r64,imm64 = 48 b8..bf imm64 (direct address load).
  5) Report hits with VA and disasm context.
"""
import os, json, struct, ctypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
with open(os.path.join(OUT,"manifest.json")) as f:
    manifest = json.load(f)

# region lookup
def rpath(r): return os.path.join(OUT, r["file"])
def read_region(r):
    with open(rpath(r),"rb") as f: return f.read()

# 1) find string VAs
NEEDLE = "禁止调试软件, 请关闭调试器然后重新运行!".encode("utf-16-le")
NEEDLE2 = "禁止调试".encode("utf-16-le")
needles = {
    "禁止调试全文": NEEDLE,
    "禁止调试短": NEEDLE2,
    "SProtect": b"S\x00P\x00r\x00o\x00t\x00e\x00c\x00t\x00",
    "请关闭调试器": "请关闭调试器".encode("utf-16-le"),
}
# also ASCII SProtect
needles["SProtect_ascii"] = b"SProtect"

string_vas = []  # (va, needle_name, region_base, offset_in_region)
print("=== locating needles ===")
for r in manifest:
    data = read_region(r)
    base = r["base"]
    for nm, nl in needles.items():
        idx = 0
        while True:
            i = data.find(nl, idx)
            if i < 0: break
            va = base + i
            string_vas.append((va, nm, base, i, r["prot"], r["type"]))
            print(f"  '{nm}' VA=0x{va:x} in region 0x{base:x} +0x{i:x} prot0x{r['prot']:x} type0x{r['type']:x}")
            idx = i + 1

if not string_vas:
    print("no needle found"); raise SystemExit

# 2) identify EXECUTE regions to scan for code refs
exec_regions = [r for r in manifest if r["prot"] in (0x20,0x40,0x10) and r["type"]==0x1000000]
print(f"\n=== scanning {len(exec_regions)} EXECUTE regions for code refs ===")

# target set
targets = {va for va,_,_,_,_,_ in string_vas}
# also include any VA within +-0x40 of a needle (string often part of struct)
target_ranges = []
for va,_,_,_,_,_ in string_vas:
    target_ranges.append((va, va+0x80))

def in_target(addr):
    for (s,e) in target_ranges:
        if s <= addr < e: return True
    return False

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

hits = []
for r in exec_regions:
    base = r["base"]
    data = read_region(r)
    # linear sweep (fast enough; regions up to ~16MB). Use capstone on whole region in chunks.
    CHUNK = 0x100000
    for off in range(0, len(data), CHUNK):
        chunk = data[off:off+CHUNK]
        for ins in md.disasm(chunk, base+off):
            # check RIP-relative LEA/MOV with mem displacement
            if ins.op_str and "rip" in ins.op_str:
                # capstone resolves rip-relative target in operands
                for op in ins.operands:
                    if op.type == CS_OP_MEM and op.mem.base != 0:
                        # rip-relative: target = next_insn_addr + disp
                        # capstone gives disp; compute
                        # need insn next address
                        target = ins.address + ins.size + op.mem.disp
                        if in_target(target):
                            hits.append((ins.address, base+off, ins.mnemonic, ins.op_str, target))
            # direct imm64 mov
            if ins.mnemonic == "mov" and "0x" in ins.op_str:
                for op in ins.operands:
                    if op.type == CS_OP_IMM and in_target(op.imm):
                        hits.append((ins.address, base+off, ins.mnemonic, ins.op_str, op.imm))

print(f"\n=== code references to anti-debug strings: {len(hits)} ===")
for (addr, rbase, mn, ops, tgt) in hits[:40]:
    print(f"  0x{addr:x} (region 0x{rbase:x}): {mn} {ops}  -> target 0x{tgt:x}")

# save
with open(os.path.join(OUT,"antidebug_refs.txt"),"w") as f:
    for (addr, rbase, mn, ops, tgt) in hits:
        f.write(f"0x{addr:x}\tregion 0x{rbase:x}\t{mn} {ops}\t-> 0x{tgt:x}\n")
print(f"\nsaved -> antidebug_refs.txt ({len(hits)} refs)")
