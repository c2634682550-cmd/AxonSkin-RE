"""
Find SProtect anti-debug in the on-disk .rr4 section.
The packer stub code is on disk in .rr4 (RawSize non-zero).
We disassemble it and locate:
  - calls to USER32 APIs (the IAT has USER32!SetTimer etc, but the stub likely
    resolves MessageBoxW dynamically or via a local import)
  - string references to "禁止调试" etc (but those are UTF-16 and may be built
    on the fly or stored encrypted)
Instead, we look for the stub's known patterns:
  - API resolution via PEB->Ldr hash walking (typical packer)
  - calls to IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent
    resolved by hash
  - the MessageBoxW call that shows the dialog
We scan .rr4 on-disk bytes for: typical anti-debug API name hashes, and for
  mov r9d/mov r8d sequences preceding a call (MessageBoxW args).
Also extract all ASCII strings >=4 from .rr4 on-disk to find API names or debug strings.
"""
import struct, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
import pefile
pe = pefile.PE(SRC, fast_load=True)
pe.parse_data_directories()

# find .rr4 section
rr4 = None
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1","replace")
    if nm == ".rr4":
        rr4 = s
        print(f".rr4 VA=0x{s.VirtualAddress:x} RawPtr=0x{s.PointerToRawData:x} RawSize=0x{s.SizeOfRawData:x} VS=0x{s.Misc_VirtualSize:x}")
        break
if not rr4:
    raise SystemExit("no .rr4")

# read on-disk .rr4 data
with open(SRC,"rb") as f:
    f.seek(rr4.PointerToRawData)
    data = f.read(rr4.SizeOfRawData)

print(f"\n.rr4 on-disk size: {len(data)} bytes ({len(data)/1048576:.1f}MB)")

# 1) strings ASCII >=5
import re
asc = re.findall(b"[\x20-\x7e]{5,}", data)
from collections import Counter
print(f"\n=== ASCII strings >=5 chars: {len(asc)} ===")
# show interesting ones
interesting = [s for s in asc if any(k in s.lower() for k in [b"debug",b"dbg",b"messag",b"protect",b"sprotect",b"trial",b"inject",b"hook",b"vm",b"detect",b"query",b"process",b"ntquery",b"info",b"present",b"remote",b"kernel",b"user32",b"ntdll",b"loadlib",b"getproc",b".dll",b"exception",b"break"])]
print(f"interesting ({len(interesting)}):")
for s in interesting[:80]:
    print(f"  {s.decode('latin1','replace')}")

# 2) disassemble .rr4 with VA = ImageBase + .rr4.VA
base_va = pe.OPTIONAL_HEADER.ImageBase + rr4.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# scan for API-hash resolution patterns and calls
# common SProtect/MPRESS: xor edx,edx; imul / or with constants then call
# Also scan for lea/mov referencing strings.
# Strategy: find all CALL instructions (e8 rel32, ff15 indirect, ff25, ff2x) and
# report density, plus find "cmp/jz" sequences near call patterns (anti-debug branches).
calls = []
anti = []
total_ins = 0
# disassemble in 1MB chunks
CHUNK = 0x100000
for off in range(0, len(data), CHUNK):
    chunk = data[off:off+CHUNK]
    for ins in md.disasm(chunk, base_va+off):
        total_ins += 1
        if ins.mnemonic == "call":
            calls.append(ins.address)
        # anti-debug patterns: cmp with 0x31/0x10 (DBG_CONT/DBG-), or test eax,eax then jz near a MessageBox-ish call
        if ins.mnemonic in ("je","jne","jz","jnz") and "eip" not in ins.op_str:
            pass
print(f"\ntotal instructions disasmed: {total_ins}")
print(f"total CALL instructions: {len(calls)}")

# 3) Look for MessageBoxW resolution: the stub often references "user32.dll" hash
# and "MessageBoxW" hash. SProtect uses 32-bit FNV/AP hash. Hard to match without table.
# Instead: find the anti-debug dialog string. It's UTF-16 but might appear encrypted.
# Search .rr4 for any 2-byte pattern that could be the dialog text XORed with a constant.
# Simpler: search the WHOLE exe for "禁止调试" utf16 (in case it's stored elsewhere)
with open(SRC,"rb") as f:
    full = f.read()
n1 = full.find("禁止调试软件".encode("utf-16-le"))
n2 = full.find("禁止调试".encode("utf-16-le"))
n3 = full.find("调试器".encode("utf-16-le"))
n4 = full.find("SProtect".encode("utf-16-le"))
print(f"\nutf16 '禁止调试软件' in full exe: {hex(n1) if n1>=0 else 'not found'}")
print(f"utf16 '禁止调试' in full exe: {hex(n2) if n2>=0 else 'not found'}")
print(f"utf16 '调试器' in full exe: {hex(n3) if n3>=0 else 'not found'}")
print(f"utf16 'SProtect' in full exe: {hex(n4) if n4>=0 else 'not found'}")
# ascii
a1 = full.find(b"SProtect")
print(f"ascii 'SProtect': {hex(a1) if a1>=0 else 'not found'}")

# 4) Also scan .a1 section (the other on-disk data section) for these strings
a1 = None
for s in pe.sections:
    if s.Name.rstrip(b"\x00")==b".a1": a1=s
if a1:
    with open(SRC,"rb") as f:
        f.seek(a1.PointerToRawData); a1data=f.read(a1.SizeOfRawData)
    for nm,pat in [("禁止调试utf16","禁止调试".encode("utf-16-le")),("SProtect_ascii",b"SProtect"),("trial_ascii",b"trial"),("试用_utf16","试用".encode("utf-16-le"))]:
        i=a1data.find(pat)
        print(f"  .a1 {nm}: {hex(i) if i>=0 else 'not found'}")
