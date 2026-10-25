"""IDAPython: Load .a1 code as raw binary with correct processor and base address.
Run with: idat.exe -A -S"this_script.py" -L"log.txt" input_file
"""
import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_pro
import ida_bytes
import ida_funcs
import sys
import os

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
os.makedirs(OUT_DIR, exist_ok=True)

code_base = 0x7FF7935DB000

# Wait for initial auto-analysis (if any)
ida_auto.auto_wait()

# Check what we got
imagebase = idaapi.get_imagebase()
print(f"[*] Image base: 0x{imagebase:x}")
print(f"[*] Min EA: 0x{idc.get_inf_attr(idc.INF_MIN_EA):x}")
print(f"[*] Max EA: 0x{idc.get_inf_attr(idc.INF_MAX_EA):x}")
print(f"[*] Is 64bit: {idc.get_inf_attr(idc.INF_LFLAGS) & 0x4 != 0}")

# Check if we have any bytes
first_bytes = ida_bytes.get_bytes(imagebase, 32)
if first_bytes:
    print(f"[*] First 32 bytes: {first_bytes.hex()}")
else:
    print("[!] No bytes at imagebase")
    # Try reading from min EA
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    first_bytes = ida_bytes.get_bytes(min_ea, 32)
    if first_bytes:
        print(f"[*] First 32 bytes at min_ea: {first_bytes.hex()}")

# Check processor
try:
    proc = ida_idaapi.get_inf_structure().procname
    print(f"[*] Processor: {proc}")
except:
    pass

# Count existing functions
funcs = list(idautils.Functions())
print(f"[*] Functions found: {len(funcs)}")

# If no functions, try manual analysis
if len(funcs) == 0:
    print("[*] No functions found. Trying to scan for prologues...")
    
    # Get the address range
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    print(f"[*] Range: 0x{min_ea:x} - 0x{max_ea:x}")
    
    # First, make sure everything is code
    ea = min_ea
    while ea < max_ea and ea < min_ea + 0x1000:
        idc.create_insn(ea)
        ea = idc.next_head(ea)
        if ea == idc.BADADDR:
            break
    
    # Scan for function prologues: 48 89 5C 24 xx
    prologue = b'\x48\x89\x5c\x24'
    search_ea = min_ea
    count = 0
    while count < 10000 and search_ea < max_ea:
        found = ida_bytes.find_bytes(prologue, search_ea, 0, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE)
        if found == idc.BADADDR or found >= max_ea:
            break
        # Make instruction and function
        idc.create_insn(found)
        ida_funcs.add_func(found)
        count += 1
        search_ea = found + 1
        if count % 1000 == 0:
            print(f"  Found {count} prologues...")
    
    print(f"[*] Total prologues found: {count}")
    ida_auto.auto_wait()
    funcs = list(idautils.Functions())
    print(f"[*] Functions after analysis: {len(funcs)}")

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
        size = end - start if end and start and end > start else 0
        f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
print(f"[*] Function list saved: {func_list_path}")

# Try Hex-Rays
hexrays_ok = False
try:
    if ida_hexrays.init_hexrays_plugin():
        hexrays_ok = True
        print("[*] Hex-Rays available")
except:
    print("[!] Hex-Rays not available")

if hexrays_ok and funcs:
    total = min(len(funcs), 500)
    print(f"[*] Decompiling {total} functions...")
    
    lines = []
    success = 0
    for i, fea in enumerate(funcs[:total]):
        try:
            cf = ida_hexrays.decompile(fea)
            if cf:
                fn = idc.get_func_name(fea)
                pc = str(cf)
                lines.append(f"\n// === {fn} @ 0x{fea:x} ===\n{pc}\n")
                success += 1
                if (i+1) % 50 == 0:
                    print(f"  [{i+1}/{total}] ok={success}")
        except Exception as e:
            lines.append(f"\n// Failed 0x{fea:x}: {e}\n")
    
    out = os.path.join(OUT_DIR, "a1_pseudocode.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"// AxonSkin v4.1 - .a1 decrypted code pseudocode\n")
        f.write(f"// Base: 0x{code_base:x}, Functions: {len(funcs)}, Decompiled: {success}/{total}\n\n")
        for l in lines:
            f.write(l)
    print(f"[*] Pseudocode: {out} ({success}/{total})")

try:
    ida_pro.save_database()
    print("[*] DB saved")
except:
    pass

print("[*] DONE")
idc.qexit(0)
