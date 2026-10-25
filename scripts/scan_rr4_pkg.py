"""Scan .rr4 (130MB) and .pkg (113MB) regions for strings and Qt class names."""
import ctypes, ctypes.wintypes as w, sys, os, re
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
if not h:
    print("Cannot open process")
    sys.exit(1)

# .rr4: VA=0xce1f000, VSize=0x8281000 (130MB)
# .pkg: VA=0x5cd9000, VSize=0x07146000 (113MB)
sections = [
    (".pkg", main_base + 0x5cd9000, 0x07146000),
    (".rr4", main_base + 0xce1f000, 0x08281000),
]

for sec_name, sec_va, sec_size in sections:
    print(f"\n{'='*60}")
    print(f"Scanning {sec_name} at VA 0x{sec_va:x}, size {sec_size/1048576:.1f}MB")
    print(f"{'='*60}")
    
    # Read in chunks
    total_strings = 0
    total_utf16 = 0
    found_regions = []
    
    chunk_size = 0x100000  # 1MB
    for offset in range(0, sec_size, chunk_size):
        read_size = min(chunk_size, sec_size - offset)
        buf = (ctypes.c_ubyte * read_size)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(sec_va + offset), buf, read_size, ctypes.byref(n))
        if ok and n.value > 0:
            data = bytes(buf[:n.value])
            
            # Check for code
            prologues = data.count(b'\x48\x89\x5c\x24')
            
            # ASCII strings
            strings = re.findall(rb'[\x20-\x7e]{15,}', data)
            if len(strings) > 5 or prologues > 20:
                found_regions.append((offset, len(strings), prologues))
            
            if strings:
                total_strings += len(strings)
                # Print interesting strings
                for s in strings:
                    s_dec = s.decode('ascii', 'replace')
                    if any(kw in s_dec for kw in ['Qt', 'Axon', 'skin', 'Skin', 'boost', 'asio', 'http', 'Dlg_', 
                           'QWidget', 'QMain', 'config', 'cache', 'license', 'auth', 'login', '.dll', '.exe',
                           'C:\\', 'VirtualProtect', 'CreateFile', 'RegOpen', 'InternetOpen',
                           'IsDebugger', 'OutputDebug', 'UpdateLayered', 'MessageBox',
                           'NTDLL', 'KERNEL32', 'USER32', 'ADVAPI32', 'SHELL32',
                           'boost::', 'std::', 'qt_', 'Q', '__']):
                        print(f"  0x{offset:08x}: {s_dec[:150]}")
            
            # Quick check for UTF-16LE
            if prologues > 20:
                print(f"  ** CODE at offset 0x{offset:08x}: prologues={prologues}")
    
    print(f"\n  Total ASCII strings: {total_strings}")
    print(f"  Regions with strings/code: {len(found_regions)}")
    for off, cnt, prol in found_regions[:20]:
        print(f"    offset 0x{off:08x} ({off//1048576}MB): strings={cnt}, prologues={prol}")

CH(h)
print("\nDONE")
