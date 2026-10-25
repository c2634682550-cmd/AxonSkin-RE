"""IDAPython headless script: export functions, strings, imports, pseudocode."""
import idaapi, idautils, idc, ida_auto, ida_nalt, ida_funcs, ida_name, ida_hexrays, ida_segment, ida_bytes
import os, sys

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
try: os.makedirs(OUT, exist_ok=True)
except: pass

ida_auto.auto_wait()
print(f"[+] database loaded: {ida_nalt.get_input_file_path()}")

# wait for analysis
print("[+] analysis done, exporting...")

# 1) segments
with open(os.path.join(OUT,"segments.txt"),"w") as f:
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        f.write(f"{ida_segment.get_segm_name(seg)} 0x{seg.start_ea:x}-0x{seg.end_ea:x} size=0x{seg.end_ea-seg.start_ea:x}\n")

# 2) functions
funcs = list(idautils.Functions())
print(f"[+] functions: {len(funcs)}")
with open(os.path.join(OUT,"functions.txt"),"w") as f:
    for ea in funcs:
        fn = ida_funcs.get_func(ea)
        nm = ida_name.get_name(ea)
        f.write(f"0x{ea:x}\t{nm}\tsize=0x{fn.end_ea-fn.start_ea if fn else 0:x}\n")

# 3) imports
with open(os.path.join(OUT,"imports.txt"),"w") as f:
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        mod = idaapi.get_import_module_name(i)
        def cb(ea, name, ordn):
            f.write(f"{mod}\t{'#'+str(ordn) if name is None else name}\t0x{ea:x}\n")
            return True
        idaapi.enum_import_names(i, cb)

# 4) strings
with open(os.path.join(OUT,"strings.txt"),"w") as f:
    for s in idautils.Strings():
        try:
            f.write(f"0x{s.ea:x}\t{s.length}\t{str(s)}\n")
        except: pass

# 5) pseudocode of EP + first N functions (Hex-Rays)
try:
    ida_hexrays.init_hexrays_plugin()
    has_hr = True
except:
    has_hr = False
print(f"[+] Hex-Rays available: {has_hr}")

if has_hr:
    ep = idc.get_inf_attr(idc.INF_START_EA)
    cfunc = ida_hexrays.decompile(ep)
    if cfunc:
        with open(os.path.join(OUT,"ep_pseudocode.txt"),"w") as f:
            f.write(str(cfunc))
    # decompile first 200 named functions
    with open(os.path.join(OUT,"pseudocode_top.txt"),"w") as f:
        cnt=0
        for ea in funcs:
            nm = ida_name.get_name(ea)
            if nm and not nm.startswith("sub_"):
                try:
                    cf = ida_hexrays.decompile(ea)
                    if cf:
                        f.write(f"\n// === {nm} @ 0x{ea:x} ===\n{cf}\n")
                        cnt+=1
                except: pass
            if cnt>=200: break
        print(f"[+] decompiled {cnt} named functions")

print("[+] DONE export")
idc.qexit(0)
