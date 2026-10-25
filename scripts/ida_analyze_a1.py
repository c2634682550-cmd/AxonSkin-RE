"""IDAPython script: analyze the decrypted .a1 code region as raw binary.
Load as x86-64, auto-analyze, decompile key functions, export results."""
import idaapi, idautils, idc, ida_funcs, ida_auto, ida_hexrays, ida_loader, ida_segment
import sys, os

# This script runs inside IDA (idat.exe -A -S"script.py" input_file)
# The file is loaded as raw binary x86-64

# Set output directory
OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
os.makedirs(OUT_DIR, exist_ok=True)

# Set the image base to the code VA
# .a1 code starts at 0x7ff7935db000
code_base = 0x7ff7935db000

# Wait for auto-analysis to complete
ida_auto.auto_wait()

# Get info
print(f"[*] File: {idc.get_input_file_path()}")
print(f"[*] Image base: 0x{idaapi.get_imagebase():x}")

# Set image base
idaapi.rebase_program(code_base - idaapi.get_imagebase(), idaapi.MF_OK)
ida_auto.auto_wait()
print(f"[*] Rebased to 0x{idaapi.get_imagebase():x}")

# Count functions
funcs = list(idautils.Functions())
print(f"[*] Functions found: {len(funcs)}")

# Try to enable Hex-Rays
try:
    if ida_hexrays.init_hexrays_plugin():
        print("[*] Hex-Rays decompiler available")
        hexrays_ok = True
    else:
        print("[!] Hex-Rays not available")
        hexrays_ok = False
except:
    hexrays_ok = False

# Decompile functions and export pseudocode
if hexrays_ok:
    # Decompile first 200 functions (or all if less)
    total = min(len(funcs), 200)
    print(f"[*] Decompiling {total} functions...")
    
    output = []
    for i, func_ea in enumerate(funcs[:total]):
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                func_name = idc.get_func_name(func_ea)
                pseudocode = str(cfunc)
                output.append(f"\n// === {func_name} @ 0x{func_ea:x} ===\n{pseudocode}\n")
                if (i+1) % 20 == 0:
                    print(f"  [{i+1}/{total}] 0x{func_ea:x} {func_name}")
        except Exception as e:
            output.append(f"\n// Failed at 0x{func_ea:x}: {e}\n")
    
    # Write pseudocode
    out_path = os.path.join(OUT_DIR, "a1_pseudocode.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"// AxonSkin v4.1 - Decrypted .a1 code region pseudocode\n")
        f.write(f"// Code base: 0x{code_base:x}\n")
        f.write(f"// Total functions: {len(funcs)}\n")
        f.write(f"// Decompiled: {total}\n\n")
        for line in output:
            f.write(line)
    print(f"[*] Pseudocode saved to {out_path}")
    
    # Also save function list
    func_list_path = os.path.join(OUT_DIR, "a1_func_list.txt")
    with open(func_list_path, "w", encoding="utf-8") as f:
        f.write(f"// Function list (.a1 code region)\n")
        f.write(f"// Code base: 0x{code_base:x}\n")
        f.write(f"// Total functions: {len(funcs)}\n\n")
        for ea in funcs:
            name = idc.get_func_name(ea)
            size = idc.get_func_attr(ea, idc.FUNCATTR_END) - idc.get_func_attr(ea, idc.FUNCATTR_START)
            f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
    print(f"[*] Function list saved to {func_list_path}")
else:
    # Just export function list
    func_list_path = os.path.join(OUT_DIR, "a1_func_list.txt")
    with open(func_list_path, "w", encoding="utf-8") as f:
        f.write(f"// Function list (.a1 code region)\n")
        f.write(f"// Code base: 0x{code_base:x}\n")
        f.write(f"// Total functions: {len(funcs)}\n\n")
        for ea in funcs:
            name = idc.get_func_name(ea)
            size = idc.get_func_attr(ea, idc.FUNCATTR_END) - idc.get_func_attr(ea, idc.FUNCATTR_START)
            f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
    print(f"[*] Function list saved to {func_list_path}")

# Save IDB
idb_path = idc.get_idb_path()
print(f"[*] IDB: {idb_path}")

ida_pro = False
try:
    import ida_pro
    ida_pro = True
except:
    pass

if ida_pro:
    ida_pro.save_database()
    print("[*] Database saved")

print("[*] DONE")
idc.qexit(0)
