"""Decompile specific key functions from axonlogin.dll to understand login/trial/auth flow."""
import idaapi, idautils, idc, ida_auto, ida_hexrays, ida_funcs, ida_name
import os

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

# key functions to decompile (from functions.txt + SP_Init chain)
targets = [
    0x18000DB40,   # SP_Init_v2 tail - real init
    0x180008480,   # DialogFunc
    0x180012720,   # SP_Init_v2
    # functions near SP_Init and DialogFunc that handle logic
    0x180005820,   # called from DialogFunc
    0x180012BF0,   # SetWindowLongPtr target from DialogFunc
    0x1800017C0,   # error handler
    0x18001A230,   # string length
    0x180007BC0,   # buffer alloc
    0x1800014F0,   # cancel_current_task helper
    0x1800150B0, 0x1800150D8,
]

# also decompile ALL functions in .text that are reachable from DialogFunc
# get all functions and decompile first 400 (to cover the login logic)
all_funcs = list(idautils.Functions())
print(f"total funcs: {len(all_funcs)}")

with open(os.path.join(OUT,"pseudocode_key.txt"),"w") as f:
    # decompile targets first
    for ea in targets:
        fn = ida_funcs.get_func(ea)
        if fn:
            try:
                cf = ida_hexrays.decompile(ea)
                if cf:
                    nm = ida_name.get_name(ea)
                    f.write(f"\n// === {nm} @ 0x{ea:x} (size 0x{fn.end_ea-fn.start_ea:x}) ===\n")
                    f.write(str(cf))
                    f.write("\n")
            except Exception as e:
                f.write(f"\n// === 0x{ea:x} decompile failed: {e} ===\n")

    # decompile ALL functions in .text section (the whole login DLL code)
    text_seg = None
    for s in idautils.Segments():
        nm = idc.get_segm_name(s)
        if nm == ".text":
            text_seg = (s, idc.get_segm_end(s))
            break
    if text_seg:
        cnt = 0
        for fea in all_funcs:
            if text_seg[0] <= fea < text_seg[1]:
                # skip already decompiled
                if fea in targets: continue
                fn = ida_funcs.get_func(fea)
                if not fn or fn.end_ea-fn.start_ea < 0x20: continue
                try:
                    cf = ida_hexrays.decompile(fea)
                    if cf:
                        nm = ida_name.get_name(fea)
                        f.write(f"\n// === {nm} @ 0x{fea:x} (size 0x{fn.end_ea-fn.start_ea:x}) ===\n")
                        f.write(str(cf))
                        f.write("\n")
                        cnt += 1
                except: pass
        f.write(f"\n// total decompiled in .text: {cnt}\n")
        print(f"decompiled {cnt} in .text")
print("done")
idc.qexit(0)
