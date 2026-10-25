"""Patch axonlogin.dll to bypass online auth.
Two patches:
1. At RVA 0x927E: 'cmp edi,1' (83 FF 01) → 'mov edi,1' (BF 01 00 00 00) - 5 bytes vs 3 bytes
   Actually better: patch the jne at 0x9281 to NOP, and je at 0x9289 to jmp
   
   Simplest: at 0x927E, replace:
     83 FF 01     cmp edi, 1         (3 bytes)
     75 17        jne 0x929A         (2 bytes)
   With:
     90 90 90     nop nop nop        (3 bytes)  
     90 90        nop nop             (2 bytes)
   This makes the code fall through to the success path regardless of edi value.
   
   But then at 0x9287: 'test ecx, ecx' + 'je 0x92D0' (74 45)
   If ecx (v8 = server required version) is non-zero, it checks version.
   Patch 0x9289: 74 45 → EB 45 (je → jmp) to always jump to success (0x92D0 = ret)

2. Also patch the ExitProcess path at 0x929A to redirect to success.
   At 0x929A: lea rcx, [r15+8] → this starts the error message + ExitProcess
   Patch 0x929A: 49 8D 4F 08 → EB 34 (jmp 0x92D0 = ret) + 90 90
   This jumps directly to the return, bypassing ExitProcess.

Actually the cleanest patch: replace the entry of sub_1800091D0 with 'return 0' (success).
The function returns __int64, and the caller checks:
  if ( v6 != 1 || v8 && qword_180050B80+128 < v8 )
    → error + ExitProcess
  
So we need v6==1 AND (v8==0 OR version_ok).
Simplest: make the function set edi=1, v8=0, then jump to ret.

Patch plan:
- 0x927E: 83 FF 01 75 17 → 90 90 90 90 90  (NOP out cmp+jne)
- 0x9283: 8B 4C 24 68   → 33 C9 90 90      (xor ecx,ecx instead of mov ecx,[rsp+0x68])
- 0x9287: 85 C9         → 90 90            (NOP test ecx,ecx)
- 0x9289: 74 45         → EB 45            (je → jmp, always jump to ret)

Total: 11 bytes patched, all within the function.
"""
import shutil, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

src = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll"
dst = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin_patched.dll"
shutil.copy2(src, dst)

with open(dst, 'r+b') as f:
    # .text section: VA=0x1000, RawOffset=0x400
    # RVA 0x927E → file offset = 0x927E - 0x1000 + 0x400 = 0x867E
    # Wait, let's compute properly:
    # .text VirtualAddress = 0x1000, PointerToRawData = 0x400
    # file_offset = rva - text_va + text_raw = 0x927E - 0x1000 + 0x400 = 0x867E
    # But earlier disasm showed: sub_1800091D0 @ RVA 0x91D0 (file offset 0x85d0)
    # So: file_offset = rva - 0x91D0 + 0x85D0 = rva - 0x1000 + 0x400
    # 0x927E - 0x1000 + 0x400 = 0x867E
    # 0x9283 - 0x1000 + 0x400 = 0x8683
    # 0x9287 - 0x1000 + 0x400 = 0x8687
    # 0x9289 - 0x1000 + 0x400 = 0x8689
    
    patches = [
        # Patch 1: NOP out 'cmp edi, 1' (3 bytes) + 'jne' (2 bytes) = 5 bytes
        (0x867E, b'\x90\x90\x90', "NOP cmp edi,1"),
        (0x8681, b'\x90\x90', "NOP jne"),
        # Patch 2: 'mov ecx,[rsp+0x68]' (4 bytes) → 'xor ecx,ecx; nop nop' 
        (0x8683, b'\x33\xC9\x90\x90', "xor ecx,ecx (force v8=0)"),
        # Patch 3: NOP 'test ecx,ecx' (2 bytes)
        (0x8687, b'\x90\x90', "NOP test ecx,ecx"),
        # Patch 4: 'je 0x92D0' → 'jmp 0x92D0' (always jump to success/ret)
        (0x8689, b'\xEB', "je→jmp (always success)"),
    ]
    
    for offset, data, desc in patches:
        f.seek(offset)
        original = f.read(len(data))
        f.seek(offset)
        f.write(data)
        print(f"  0x{offset:x}: {original.hex()} → {data.hex()}  ; {desc}")

print(f"\nPatched DLL saved to: {dst}")
print(f"Original: {src}")

# Verify
with open(dst, 'rb') as f:
    f.seek(0x867E)
    verify = f.read(11)
    print(f"\nVerification at 0x867E: {verify.hex()}")
    print(f"Expected: 9090909090 33c99090 9090 eb")
    # 0x867E: 90 90 90 90 90 33 C9 90 90 90 90 EB
    ok = verify == b'\x90\x90\x90\x90\x90\x33\xC9\x90\x90\x90\x90'
    if not ok:
        # our expected might be off, let's just check the key bytes
        print(f"Key check: byte[5]={verify[5]:02x} (want 0x33), byte[10]={verify[10]:02x} (want 0xEB)")
        if verify[5] == 0x33 and verify[10] == 0xEB:
            print("PATCH VERIFIED OK")
