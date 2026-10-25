"""IDAPython v6: Manual byte-by-byte scan for prologues.
Uses get_bytes + comparison instead of find_bytes API."""
import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
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

min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
print(f"[*] Range: 0x{min_ea:x} - 0x{max_ea:x}")
print(f"[*] LFLAGS: 0x{idc.get_inf_attr(idc.INF_LFLAGS):x}")

# Set 64-bit mode
lflags = idc.get_inf_attr(idc.INF_LFLAGS)
idc.set_inf_attr(idc.INF_LFLAGS, lflags | 0x40)
print(f"[*] LFLAGS after: 0x{idc.get_inf_attr(idc.INF_LFLAGS):x}")

# Read the entire binary in chunks and scan for prologues
print("[*] Scanning for prologues (manual byte scan)...")
prologue = bytes([0x48, 0x89, 0x5c, 0x24])
count = 0
chunk_size = 0x100000  # 1MB chunks
total_size = max_ea - min_ea

for chunk_start in range(0, total_size, chunk_size):
    read_size = min(chunk_size, total_size - chunk_start)
    ea_start = min_ea + chunk_start
    
    # Read bytes
    data = ida_bytes.get_bytes(ea_start, read_size)
    if not data:
        continue
    
    # Scan for prologue
    pos = 0
    while pos < len(data) - 4:
        if data[pos:pos+4] == prologue:
            found_ea = ea_start + pos
            # Create instruction and function
            idc.create_insn(found_ea)
            ida_funcs.add_func(found_ea)
            count += 1
            pos += 1  # Don't skip, might overlap
        else:
            pos += 1
    
    if count % 2000 < 100 and count > 0:
        print(f"  Chunk 0x{chunk_start:x}: {count} prologues total")
    elif (chunk_start // chunk_size) % 5 == 0:
        print(f"  Chunk 0x{chunk_start:x} ({chunk_start//1048576}MB): {count} total so far")

print(f"[*] Total prologues: {count}")

# Auto-analyze
ida_auto.auto_wait()
funcs = list(idautils.Functions())
print(f"[*] Functions after analysis: {len(funcs)}")

# Save function list
fl_path = os.path.join(OUT_DIR, "a1_func_list.txt")
with open(fl_path, "w", encoding="utf-8") as f:
    f.write(f"// Function list (.a1 code)\n// Range: 0x{min_ea:x}-0x{max_ea:x}\n// Functions: {len(funcs)}\n\n")
    for ea in funcs:
        name = idc.get_func_name(ea)
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        size = (end - start) if end and start and end > start else 0
        f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
print(f"[*] Saved: {fl_path}")

# Decompile
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
