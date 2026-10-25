"""Extract the real code from .a1 section dump (0x7ff7925db000, 30MB).
The code starts at offset 0x1000000 (16MB) where we found function prologues.
Also try reading this region from the live process now."""
import sys, os, struct, re, ctypes, ctypes.wintypes as w
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re"

# Method 1: Use the previously dumped .a1 region from unpack6
a1_file = os.path.join(WORK, "unpack6", "r_00007ff7925db000_01dfd000_p20_t1000000.bin")
if os.path.exists(a1_file):
    with open(a1_file, "rb") as f:
        a1_data = f.read()
    print(f"=== .a1 region from unpack6: {len(a1_data)/1048576:.1f}MB ===")
    
    # Extract the code portion (offset 0x1000000+)
    code_start = 0x1000000  # 16MB offset
    code_data = a1_data[code_start:]
    print(f"Code portion (offset 0x{code_start:x}): {len(code_data)/1048576:.1f}MB")
    
    # Verify prologues
    for i in range(0, len(code_data), 0x100000):
        chunk = code_data[i:i+0x100000]
        if len(chunk) < 0x1000:
            break
        prol = chunk.count(b'\x48\x89\x5c\x24')
        calls = chunk.count(b'\xe8') + chunk.count(b'\xff\x15')
        if prol > 10:
            print(f"  offset 0x{i:x} ({i//1048576}MB): prol={prol} calls={calls}")
    
    # Also check for strings in the first 16MB (SProtect stub)
    stub_data = a1_data[:code_start]
    ascii_strings = re.findall(rb'[\x20-\x7e]{10,}', stub_data[:0x200000])
    print(f"\nSProtect stub strings (first 2MB): {len(ascii_strings)}")
    for s in ascii_strings[:20]:
        print(f"  {s.decode('ascii','replace')[:100]}")
    
    # Save the code portion
    out_code = os.path.join(WORK, "unpack7", "a1_code_region.bin")
    with open(out_code, "wb") as f:
        f.write(code_data)
    print(f"\nSaved code region: {len(code_data)/1048576:.1f}MB to {out_code}")
    
    # Also check the full .a1 for interesting strings
    utf16_strings = []
    i = 0
    while i < len(a1_data) - 4:
        if a1_data[i+1] == 0 and 0x20 <= a1_data[i] <= 0x7e:
            j = i
            while j < len(a1_data) - 1:
                lo = a1_data[j]
                hi = a1_data[j+1]
                if hi == 0 and 0x20 <= lo <= 0x7e:
                    j += 2
                elif hi > 0:
                    j += 2
                else:
                    break
            if (j - i) >= 24:  # 12+ chars
                raw = a1_data[i:j]
                try:
                    decoded = raw.decode('utf-16-le', errors='replace')
                    if len(decoded.strip()) >= 6:
                        utf16_strings.append((i, decoded.strip()))
                except:
                    pass
            i = j + 2
        else:
            i += 1
    
    print(f"\nUTF-16LE strings in .a1: {len(utf16_strings)}")
    for off, s in utf16_strings[:30]:
        print(f"  0x{off:08x}: {s[:120]}")

# Method 2: Read from live process
print(f"\n=== Reading .a1 from live process ===")
PID = 54824
main_base = 0x7ff78e700000
a1_va = main_base + 0x3edb000  # .a1 VA = 0x3edb000
a1_size = 0x1dfd000

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
OP = k32.OpenProcess; OP.argtypes = [w.DWORD, w.BOOL, w.DWORD]; OP.restype = w.HANDLE
RPM = k32.ReadProcessMemory; RPM.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]; RPM.restype = w.BOOL
CH = k32.CloseHandle

h = OP(PROCESS_ALL_ACCESS, False, PID)
if h:
    # Read the code portion of .a1
    code_offset = 0x1000000  # Start of real code
    read_size = a1_size - code_offset
    buf = (ctypes.c_ubyte * read_size)()
    n = ctypes.c_size_t(0)
    ok = RPM(h, ctypes.c_void_p(a1_va + code_offset), buf, read_size, ctypes.byref(n))
    if ok and n.value > 0:
        live_data = bytes(buf[:n.value])
        prol = live_data[:0x100000].count(b'\x48\x89\x5c\x24')
        print(f"  Read {n.value/1048576:.1f}MB from live process, prologues in 1st MB: {prol}")
        
        # Compare with dump
        if os.path.exists(a1_file):
            with open(a1_file, "rb") as f:
                dump_data = f.read()
            dump_code = dump_data[code_offset:]
            
            # Check differences
            diffs = 0
            for i in range(0, min(len(live_data), len(dump_code)), 0x1000):
                if live_data[i:i+16] != dump_code[i:i+16]:
                    diffs += 1
            print(f"  Page differences vs dump: {diffs} (of {min(len(live_data), len(dump_code))//0x1000})")
            
            # Check if dump had more data
            if len(dump_code) > len(live_data):
                print(f"  Dump has {len(dump_code) - len(live_data)} more bytes")
        
        # Save live code
        out_live = os.path.join(WORK, "unpack7", "a1_code_live.bin")
        with open(out_live, "wb") as f:
            f.write(live_data)
        print(f"  Saved to {out_live}")
    else:
        print(f"  RPM failed (err={ctypes.get_last_error()})")
    CH(h)
else:
    print(f"  OpenProcess failed (err={ctypes.get_last_error()})")

# Also check .rr4 section - VA=0xce1f000, VSize=130MB - this might contain the real code
print(f"\n=== Checking .rr4 section ===")
rr4_va = main_base + 0xce1f000
rr4_size = 0x8281000  # 130MB

if h:
    h = OP(PROCESS_ALL_ACCESS, False, PID)
    if h:
        # Read first 1MB of .rr4
        buf = (ctypes.c_ubyte * 0x100000)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(rr4_va), buf, 0x100000, ctypes.byref(n))
        if ok and n.value > 0:
            rr4_data = bytes(buf[:n.value])
            prol = rr4_data.count(b'\x48\x89\x5c\x24')
            zeros = rr4_data.count(b'\x00')
            print(f"  .rr4 first 1MB: prologues={prol}, zeros={zeros/0x100000*100:.1f}%")
            print(f"  First 32 bytes: {rr4_data[:32].hex()}")
        CH(h)
