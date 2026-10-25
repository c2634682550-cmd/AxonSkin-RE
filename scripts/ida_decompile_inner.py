"""Decompile axon_inner.bin focusing on:
- Dlg_Main (main program UI)
- Dlg_Login (login dialog)
- VirtualProtect calls (.text decryption)
- IsDebuggerPresent (anti-debug)
- InternetGetConnectedState (network check)
"""
import idaapi, idautils, idc, ida_auto, ida_hexrays, ida_funcs, ida_name, ida_segment
import os, struct

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

print(f"[+] loaded: {idaapi.get_input_file_path()}")

# Get all function names
all_funcs = list(idautils.Functions())
print(f"[+] functions: {len(all_funcs)}")

# Find Dlg_Main, Dlg_Login, SP_Init, entry point
key_names = {}
for ea in all_funcs:
    nm = ida_name.get_name(ea)
    if nm and not nm.startswith("sub_"):
        if any(k in nm for k in ["Dlg_Main","Dlg_Login","Dlg_RMBind","Dlg_Online","SP_Init","Entry","entry","_main","wWinMain","WinMain","start","DllMain"]):
            key_names[ea] = nm

print("[+] key named functions:")
for ea, nm in sorted(key_names.items()):
    fn = ida_funcs.get_func(ea)
    sz = fn.end_ea - fn.start_ea if fn else 0
    print(f"  0x{ea:x} {nm} size=0x{sz:x}")

# Also find functions that call VirtualProtect, IsDebuggerPresent, InternetGetConnectedState
# These are via IAT - find the IAT entries
vp_ea = 0; idp_ea = 0; igc_ea = 0
for ea in all_funcs:
    nm = ida_name.get_name(ea)
    if nm and "VirtualProtect" in nm:
        vp_ea = ea
    if nm and "IsDebuggerPresent" in nm:
        idp_ea = ea
    if nm and "InternetGetConnectedState" in nm:
        igc_ea = ea

print(f"[+] VirtualProtect IAT: 0x{vp_ea:x}")
print(f"[+] IsDebuggerPresent IAT: 0x{idp_ea:x}")
print(f"[+] InternetGetConnectedState IAT: 0x{igc_ea:x}")

# Find all xrefs to these IAT entries
def find_callers(target_ea, label):
    callers = set()
    if target_ea:
        for xref in idautils.XrefsTo(target_ea):
            fn = ida_funcs.get_func(xref.frm)
            if fn:
                callers.add(fn.start_ea)
    return callers

vp_callers = find_callers(vp_ea, "VirtualProtect")
idp_callers = find_callers(idp_ea, "IsDebuggerPresent")
igc_callers = find_callers(igc_ea, "InternetGetConnectedState")
print(f"[+] VirtualProtect callers: {len(vp_callers)} at {[hex(x) for x in sorted(vp_callers)]}")
print(f"[+] IsDebuggerPresent callers: {len(idp_callers)} at {[hex(x) for x in sorted(idp_callers)]}")
print(f"[+] InternetGetConnectedState callers: {len(igc_callers)} at {[hex(x) for x in sorted(igc_callers)]}")

# Decompile key functions + callers
targets = set(key_names.keys()) | vp_callers | idp_callers | igc_callers

with open(os.path.join(OUT,"axon_inner_pseudocode.txt"),"w") as f:
    for ea in sorted(targets):
        fn = ida_funcs.get_func(ea)
        if not fn: continue
        try:
            cf = ida_hexrays.decompile(ea)
            if cf:
                nm = ida_name.get_name(ea)
                f.write(f"\n// === {nm} @ 0x{ea:x} (size 0x{fn.end_ea-fn.start_ea:x}) ===\n")
                f.write(str(cf))
                f.write("\n")
        except Exception as e:
            f.write(f"\n// === 0x{ea:x} decompile failed: {e} ===\n")

    # Also decompile ALL .text functions for completeness
    text_seg = None
    for s in idautils.Segments():
        if idc.get_segm_name(s) == ".text":
            text_seg = (s, idc.get_segm_end(s))
            break
    if text_seg:
        cnt = 0
        for fea in all_funcs:
            if text_seg[0] <= fea < text_seg[1]:
                if fea in targets: continue
                fn = ida_funcs.get_func(fea)
                if not fn or fn.end_ea-fn.start_ea < 0x20: continue
                try:
                    cf = ida_hexrays.decompile(fea)
                    if cf:
                        nm = ida_name.get_name(fea)
                        f.write(f"\n// === {nm} @ 0x{fea:x} ===\n{cf}\n")
                        cnt += 1
                except: pass
        f.write(f"\n// total additional in .text: {cnt}\n")
        print(f"[+] decompiled {cnt} additional in .text + {len(targets)} key")

print("[+] DONE")
idc.qexit(0)
