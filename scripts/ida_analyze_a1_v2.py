"""IDAPython: Load raw binary as x86-64, set base address, analyze, decompile."""
import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_pro
import ida_segment
import ida_bytes
import sys
import os

# Force stdout to UTF-8
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
os.makedirs(OUT_DIR, exist_ok=True)

# Code base address
code_base = 0x7FF7935DB000

# Wait for initial auto-analysis
ida_auto.auto_wait()

# Check current state
imagebase = idaapi.get_imagebase()
print(f"[*] Image base: 0x{imagebase:x}")
print(f"[*] Input file: {idc.get_input_file_path()}")

# Rebase to correct VA
if imagebase != code_base:
    delta = code_base - imagebase
    print(f"[*] Rebasing by 0x{delta:x} to 0x{code_base:x}")
    idaapi.rebase_program(delta, idaapi.MF_OK)
    ida_auto.auto_wait()
    print(f"[*] New base: 0x{idaapi.get_imagebase():x}")

# Set processor to 64-bit if not already
try:
    info = ida_idaapi.get_inf_structure()
    if not info.is_64bit():
        print("[!] Not 64-bit, trying to set...")
except:
    pass

# Count functions
funcs = list(idautils.Functions())
print(f"[*] Functions found: {len(funcs)}")

if len(funcs) == 0:
    # No functions found - try to create some by analyzing code
    print("[*] No functions found, attempting manual analysis...")
    # Try to define functions at common patterns
    # Look for function prologues: 48 89 5C 24 xx (mov [rsp+x], rbx)
    import ida_bytes
    ea = idaapi.get_imagebase()
    end_ea = ea + idaapi.get_inf_structure().max_ea - idaapi.get_inf_structure().min_ea
    
    # Actually, let's scan for prologues
    prologue = b'\x48\x89\x5c\x24'
    count = 0
    search_ea = idaapi.get_imagebase()
    while count < 5000:
        found = ida_bytes.find_bytes(prologue, search_ea)
        if found == idaapi.BADADDR:
            break
        # Try to create function here
        idc.create_insn(found)
        ida_funcs.add_func(found)
        count += 1
        search_ea = found + 1
        if count % 500 == 0:
            print(f"  Found {count} prologues so far...")
    
    ida_auto.auto_wait()
    funcs = list(idautils.Functions())
    print(f"[*] After manual analysis: {len(funcs)} functions")

# Export function list
func_list_path = os.path.join(OUT_DIR, "a1_func_list.txt")
with open(func_list_path, "w", encoding="utf-8") as f:
    f.write(f"// Function list (.a1 code region)\n")
    f.write(f"// Code base: 0x{code_base:x}\n")
    f.write(f"// Total functions: {len(funcs)}\n\n")
    for ea in funcs:
        name = idc.get_func_name(ea)
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        size = end - start if end > start else 0
        f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
print(f"[*] Function list saved: {func_list_path} ({len(funcs)} functions)")

# Try Hex-Rays decompilation
hexrays_ok = False
try:
    if ida_hexrays.init_hexrays_plugin():
        print("[*] Hex-Rays decompiler available")
        hexrays_ok = True
    else:
        print("[!] Hex-Rays not available")
except Exception as e:
    print(f"[!] Hex-Rays init failed: {e}")

if hexrays_ok:
    total = min(len(funcs), 500)
    print(f"[*] Decompiling {total} functions...")
    
    output_lines = []
    success = 0
    for i, func_ea in enumerate(funcs[:total]):
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                func_name = idc.get_func_name(func_ea)
                pseudocode = str(cfunc)
                output_lines.append(f"\n// === {func_name} @ 0x{func_ea:x} ===\n{pseudocode}\n")
                success += 1
                if (i + 1) % 50 == 0:
                    print(f"  [{i+1}/{total}] decompiled {success}")
        except Exception as e:
            output_lines.append(f"\n// Failed at 0x{func_ea:x}: {e}\n")
    
    out_path = os.path.join(OUT_DIR, "a1_pseudocode.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"// AxonSkin v4.1 - Decrypted .a1 code pseudocode\n")
        f.write(f"// Code base: 0x{code_base:x}\n")
        f.write(f"// Total functions: {len(funcs)}\n")
        f.write(f"// Decompiled: {success}/{total}\n\n")
        for line in output_lines:
            f.write(line)
    print(f"[*] Pseudocode saved: {out_path} ({success}/{total} functions)")

# Save database
try:
    ida_pro.save_database()
    print(f"[*] Database saved")
except:
    pass

print("[*] DONE")
idc.qexit(0)
