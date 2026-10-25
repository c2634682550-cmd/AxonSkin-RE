import idaapi, ida_loader, idc, ida_auto
# Load as raw binary, x86-64, 64-bit
ida_loader.load_binary_file(idc.get_input_file_path(), 0, 0, 0, 0, 0, 0, 0)
ida_auto.auto_wait()
# Now run the analysis script
exec(open(r'C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\scripts\ida_analyze_a1.py').read())
