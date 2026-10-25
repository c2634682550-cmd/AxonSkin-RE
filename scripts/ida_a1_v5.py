"""IDAPython for IDA 9.3: Load as 64-bit, analyze prologues, decompile.
Uses IDA 9.3's new API (idc.set_processor_type, inf structure via ida_ida)."""
import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
import ida_pro
import ida_bytes
import ida_funcs
import ida_segment
import ida_ida
import sys
import os

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

# IDA 9.3 uses ida_ida.inf_structure (not ida_idaapi.get_inf_structure)
# Check current state
print(f"[*] ImageBase: 0x{idaapi.get_imagebase():x}")
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
print(f"[*] Range: 0x{min_ea:x} - 0x{max_ea:x}")

# Check if 64-bit
lflags = idc.get_inf_attr(idc.INF_LFLAGS)
is_64 = bool(lflags & 0x40)  # INHIB_ADDR/GUESS bits... actually bit 6 = 64-bit
# Actually in IDA 9.3, check via ida_ida
try:
    inf = ida_ida.inf
    print(f"[*] 64-bit: {inf.is_64bit()}")
    print(f"[*] Procname: {inf.procname}")
except:
    # Fallback: check lflags
    print(f"[*] LFLAGS: 0x{lflags:x}")

# THE KEY: set to 64-bit mode
# In IDA 9.3: ida_ida.set_processor_type("metapc", ida_ida.SETPROC_FORCE)
try:
    # Force 64-bit by changing the inf bits
    # Actually the cleanest way: use set_inf_attr to set the 64-bit flag
    # INF_LFLAGS bit 0x40 = LFLG_64BIT
    current_lflags = idc.get_inf_attr(idc.INF_LFLAGS)
    new_lflags = current_lflags | 0x40  # Set 64-bit flag
    idc.set_inf_attr(idc.INF_LFLAGS, new_lflags)
    print(f"[*] Set LFLAGS: 0x{current_lflags:x} -> 0x{new_lflags:x}")
    
    # Also set the procname explicitly
    idc.set_processor_type("metapc", idc.SETPROC_FORCE)
    print("[*] Processor set to metapc")
except Exception as e:
    print(f"[!] Set 64-bit failed: {e}")

# Now scan for prologues - use raw byte search via find_bytes
print("[*] Scanning for prologues 48 89 5C 24...")
prologue = b'\x48\x89\x5c\x24'
search_ea = min_ea
count = 0
while count < 20000 and search_ea < max_ea - 4:
    try:
        # In IDA 9.3, use ida_bytes.find_bytes with proper flags
        found = ida_bytes.find_bytes(prologue, search_ea, 0, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE)
        if found == idc.BADADDR or found >= max_ea:
            break
        # Create instruction first
        idc.create_insn(found)
        # Then create function
        ida_funcs.add_func(found)
        count += 1
        search_ea = found + 1
        if count % 2000 == 0:
            print(f"  {count} prologues...")
    except Exception as e:
        if count == 0:
            print(f"[!] find_bytes failed: {e}")
            # Try alternative: manual scan
            print("[*] Trying manual byte scan...")
            ea = min_ea
            while ea < max_ea - 4 and count < 20000:
                b = ida_bytes.get_bytes(ea, 4)
                if b and b == prologue:
                    idc.create_insn(ea)
                    ida_funcs.add_func(ea)
                    count += 1
                    if count % 2000 == 0:
                        print(f"  {count} prologues...")
                ea += 1
            break
        search_ea += 1

print(f"[*] Total prologues found: {count}")

# Run auto-analysis
ida_auto.auto_wait()
funcs = list(idautils.Functions())
print(f"[*] Functions: {len(funcs)}")

OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
os.makedirs(OUT_DIR, exist_ok=True)

# Save function list
fl_path = os.path.join(OUT_DIR, "a1_func_list.txt")
with open(fl_path, "w", encoding="utf-8") as f:
    f.write(f"// Function list\n// Range: 0x{min_ea:x}-0x{max_ea:x}\n// Functions: {len(funcs)}\n\n")
    for ea in funcs:
        name = idc.get_func_name(ea)
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        size = (end - start) if end and start and end > start else 0
        f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
print(f"[*] Saved: {fl_path}")

# Hex-Rays decompilation
try:
    if ida_hexrays.init_hexrays_plugin():
        total = min(len(funcs), 500)
        print(f"[*] Decompiling {total}...")
        lines = []
        success = 0
        for i, fea in enumerate(funcs[:total]):
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    fn = idc.get_func_name(fea)
                    lines.append(f"\n// === {fn} @ 0x{fea:x} ===\n{str(cf)}\n")
                    success += 1
                    if (i+1) % 50 == 0:
                        print(f"  [{i+1}/{total}] ok={success}")
            except:
                pass
        out = os.path.join(OUT_DIR, "a1_pseudocode.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"// .a1 pseudocode, {len(funcs)} funcs, {success}/{total} decompiled\n\n")
            for l in lines:
                f.write(l)
        print(f"[*] Pseudocode: {out} ({success}/{total})")
except Exception as e:
    print(f"[!] Hex-Rays: {e}")

try:
    ida_pro.save_database()
    print("[*] DB saved")
except:
    pass

print("[*] DONE")
idc.qexit(0)
