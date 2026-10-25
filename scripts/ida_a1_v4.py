"""IDAPython: Load raw binary, set processor to metapc 64-bit, then analyze.
This script must be the FIRST thing IDA runs via -S.
IDA will load the file, and this script sets up the correct processor and base."""
import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
import ida_idaapi
import ida_pro
import ida_bytes
import ida_funcs
import sys
import os

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

# Print what IDA loaded
print(f"[*] Input: {idc.get_input_file_path()}")
print(f"[*] ImageBase: 0x{idaapi.get_imagebase():x}")
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
print(f"[*] Range: 0x{min_ea:x} - 0x{max_ea:x}")

# Check current processor
try:
    inf = ida_idaapi.get_inf_structure()
    print(f"[*] Processor: {inf.procname}")
    print(f"[*] Bits: {'64' if inf.is_64bit() else ('32' if inf.is_32bit() else '16')}")
except:
    pass

# Read first bytes to verify data is loaded
fb = ida_bytes.get_bytes(min_ea, 32)
if fb:
    print(f"[*] First bytes: {fb.hex()}")
else:
    print("[!] No bytes readable!")

# Check number of segments
import ida_segment
for seg in idautils.Segments():
    s = ida_segment.getseg(seg)
    if s:
        print(f"[*] Segment: 0x{s.start_ea:x}-0x{s.end_ea:x} name={ida_segment.get_segm_name(s)}")

# Try to set to 64-bit if not already
try:
    inf = ida_idaapi.get_inf_structure()
    if not inf.is_64bit():
        print("[*] Setting to 64-bit mode...")
        # In IDA 9.x, we can set the processor via set_processor_type
        ida_idaapi.set_processor_type("metapc", ida_idaapi.SETPROC_USER)
        # Force 64-bit
        idc.set_inf_attr(idc.INF_LFLAGS, idc.get_inf_attr(idc.INF_LFLAGS) | 0x4)  # lFLG_64BIT
        print("[*] Processor set to metapc 64-bit")
except Exception as e:
    print(f"[!] Processor set failed: {e}")

# Now scan for function prologues
print("[*] Scanning for prologues 48 89 5C 24...")
prologue = b'\x48\x89\x5c\x24'
search_ea = min_ea
count = 0
while count < 20000 and search_ea < max_ea:
    found = ida_bytes.find_bytes(prologue, search_ea, 0, ida_bytes.BIN_SEARCH_FORWARD)
    if found == idc.BADADDR or found >= max_ea:
        break
    idc.create_insn(found)
    if ida_funcs.add_func(found):
        count += 1
    search_ea = found + 1
    if count % 2000 == 0:
        print(f"  {count} prologues...")

print(f"[*] Total prologues: {count}")
ida_auto.auto_wait()

funcs = list(idautils.Functions())
print(f"[*] Functions: {len(funcs)}")

# Save function list
OUT_DIR = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
os.makedirs(OUT_DIR, exist_ok=True)

func_list_path = os.path.join(OUT_DIR, "a1_func_list.txt")
with open(func_list_path, "w", encoding="utf-8") as f:
    f.write(f"// Function list (.a1 code region)\n")
    f.write(f"// Range: 0x{min_ea:x}-0x{max_ea:x}\n")
    f.write(f"// Total functions: {len(funcs)}\n\n")
    for ea in funcs:
        name = idc.get_func_name(ea)
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        size = end - start if end and start and end > start else 0
        f.write(f"0x{ea:x}  {name}  (size: 0x{size:x})\n")
print(f"[*] Saved: {func_list_path}")

# Try Hex-Rays
try:
    if ida_hexrays.init_hexrays_plugin():
        total = min(len(funcs), 300)
        print(f"[*] Decompiling {total} functions...")
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
