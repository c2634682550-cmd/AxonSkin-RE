"""Extract:
1. .rr4 import table (first 24MB of .rr4) - API names and C++ symbols
2. .rr4 code region (offset 0x07300000+, ~15MB)
3. Combined with .a1 code (14MB), total ~29MB of decrypted code
"""
import ctypes, ctypes.wintypes as w, sys, os, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PID = 54824
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"
main_base = 0x7ff78e700000

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
OP = k32.OpenProcess; OP.argtypes = [w.DWORD, w.BOOL, w.DWORD]; OP.restype = w.HANDLE
RPM = k32.ReadProcessMemory; RPM.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]; RPM.restype = w.BOOL
CH = k32.CloseHandle

h = OP(0x1F0FFF, False, PID)
if not h:
    h = OP(0x0410, False, PID)

# .rr4: VA=0xce1f000, VSize=0x8281000
rr4_va = main_base + 0xce1f000  # 0x7ff79b51f000
rr4_size = 0x8281000  # 130MB

# Extract import table (first 24MB)
print("=== Extracting .rr4 import table (first 24MB) ===")
import_size = 0x1800000  # 24MB
buf = (ctypes.c_ubyte * import_size)()
n = ctypes.c_size_t(0)
ok = RPM(h, ctypes.c_void_p(rr4_va), buf, import_size, ctypes.byref(n))
if ok and n.value > 0:
    import_data = bytes(buf[:n.value])
    out_path = os.path.join(OUT, "rr4_imports.bin")
    with open(out_path, "wb") as f:
        f.write(import_data)
    print(f"  Saved {len(import_data)/1048576:.1f}MB to {out_path}")
    
    # Extract all API names
    strings = re.findall(rb'[\x20-\x7e]{6,}', import_data)
    print(f"  Total strings: {len(strings)}")
    
    # Categorize
    api_names = []
    dll_names = []
    cpp_symbols = []
    other = []
    for s in strings:
        s_dec = s.decode('ascii', 'replace')
        if s_dec.endswith('.dll') or s_dec.endswith('.DLL'):
            dll_names.append(s_dec)
        elif '?' in s_dec and '@' in s_dec:
            cpp_symbols.append(s_dec)
        elif s_dec[0].isupper() and any(c.islower() for c in s_dec):
            api_names.append(s_dec)
        else:
            other.append(s_dec)
    
    print(f"\n  DLL names ({len(dll_names)}):")
    for s in sorted(set(dll_names)):
        print(f"    {s}")
    
    print(f"\n  API names ({len(api_names)}, first 50):")
    for s in sorted(set(api_names))[:50]:
        print(f"    {s}")
    
    print(f"\n  C++ symbols ({len(cpp_symbols)}, first 30):")
    for s in sorted(set(cpp_symbols))[:30]:
        print(f"    {s[:150]}")

# Extract .rr4 code region (offset 0x07300000+)
print(f"\n=== Extracting .rr4 code (offset 0x07300000+) ===")
code_offset = 0x07300000
code_size = rr4_size - code_offset  # ~15MB
buf2 = (ctypes.c_ubyte * code_size)()
n2 = ctypes.c_size_t(0)
ok2 = RPM(h, ctypes.c_void_p(rr4_va + code_offset), buf2, code_size, ctypes.byref(n2))
if ok2 and n2.value > 0:
    rr4_code = bytes(buf2[:n2.value])
    out_code = os.path.join(OUT, "rr4_code.bin")
    with open(out_code, "wb") as f:
        f.write(rr4_code)
    print(f"  Saved {len(rr4_code)/1048576:.1f}MB to {out_code}")
    
    # Check prologues
    for i in range(0, len(rr4_code), 0x100000):
        chunk = rr4_code[i:i+0x100000]
        if len(chunk) < 0x1000:
            break
        prol = chunk.count(b'\x48\x89\x5c\x24')
        if prol > 5:
            print(f"    offset 0x{i:08x} ({i//1048576}MB): {prol} prologues")
    
    # Look for strings in code
    code_strings = re.findall(rb'[\x20-\x7e]{15,}', rr4_code)
    print(f"\n  Code region strings: {len(code_strings)}")
    for s in code_strings[:20]:
        print(f"    {s.decode('ascii','replace')[:120]}")
    
    # Check for Qt RTTI strings
    qt_strings = [s for s in code_strings if b'Qt' in s or b'Q' in s[:3] or b'Axon' in s or b'Dlg' in s or b'boost' in s]
    print(f"\n  Qt/interesting strings: {len(qt_strings)}")
    for s in qt_strings[:20]:
        print(f"    {s.decode('ascii','replace')[:120]}")

CH(h)
print("\nDONE")
