"""Scan ALL committed memory regions of the live process for strings.
This will find where .rdata (with strings) is actually located."""
import ctypes, ctypes.wintypes as w, sys, os, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PID = 54824
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"
main_base = 0x7ff78e700000

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MBI(ctypes.Structure):
    _fields_=[("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
        ("AllocationProtect",w.DWORD),("RegionSize",ctypes.c_size_t),
        ("State",w.DWORD),("Protect",w.DWORD),("Type",w.DWORD)]

VQ=k32.VirtualQueryEx; VQ.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.POINTER(MBI),ctypes.c_size_t]; VQ.restype=ctypes.c_size_t
RPM=k32.ReadProcessMemory; RPM.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]; RPM.restype=w.BOOL
OP=k32.OpenProcess; OP.argtypes=[w.DWORD,w.BOOL,w.DWORD]; OP.restype=w.HANDLE
CH=k32.CloseHandle

h = OP(PROCESS_ALL_ACCESS, False, PID)
if not h:
    h = OP(0x1F0FFF, False, PID)
if not h:
    h = OP(0x0410, False, PID)

if not h:
    print("Cannot open process")
    sys.exit(1)

# Query all committed regions
regions = []
addr = 0
mbi = MBI()
fails = 0
while addr < (1 << 48):
    r = VQ(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if r == 0:
        addr += 0x1000
        fails += 1
        if fails > 0x200000:
            break
        continue
    fails = 0
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize or 0
    if mbi.State == MEM_COMMIT and mbi.Protect not in (0, PAGE_NOACCESS) and not (mbi.Protect & PAGE_GUARD):
        regions.append((base, size, mbi.Protect, mbi.Type, mbi.AllocationBase))
    addr = base + size
    if addr <= (mbi.BaseAddress or 0):
        addr = (mbi.BaseAddress or 0) + 0x1000

print(f"Total committed regions: {len(regions)}")

# Scan each region for strings (only regions > 4KB and within main module)
# Main module spans from base to base + 0x150ce000
main_end = main_base + 0x150ce000

interesting_regions = []
for base, size, prot, typ, alloc_base in regions:
    if alloc_base == main_base or (main_base <= base < main_end):
        # Read first 64KB
        read_size = min(size, 0x10000)
        buf = (ctypes.c_ubyte * read_size)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(base), buf, read_size, ctypes.byref(n))
        if ok and n.value > 0:
            data = bytes(buf[:n.value])
            ascii_count = len(re.findall(rb'[\x20-\x7e]{12,}', data))
            # Check for Qt/Axon strings
            has_qt = any(kw in data for kw in [b'Qt6', b'QApp', b'QObject', b'QWidget', b'Axon', b'skin', b'boost', b'asio', b'http'])
            has_dll = any(kw in data for kw in [b'.dll', b'.exe', b'C:\\', b'kernel32', b'user32'])
            if ascii_count > 10 or has_qt or has_dll:
                interesting_regions.append((base, size, prot, ascii_count, has_qt, has_dll))

print(f"\nRegions with strings: {len(interesting_regions)}")
for base, size, prot, cnt, qt, dll in interesting_regions:
    sec_rva = (base - main_base) if main_base <= base < main_end else -1
    sec_name = ""
    # Map to section
    if sec_rva >= 0:
        if sec_rva < 0x2615000: sec_name = ".text"
        elif sec_rva < 0x3c03000: sec_name = ".rdata"
        elif sec_rva < 0x3d12000: sec_name = ".data"
        elif sec_rva < 0x3ece000: sec_name = ".pdata"
        elif sec_rva < 0x3edb000: sec_name = ".qtmimed/_RDATA"
        elif sec_rva < 0x5cd8000: sec_name = ".a1"
        elif sec_rva < 0x5cd9000: sec_name = ".k3"
        elif sec_rva < 0xce1f000: sec_name = ".pkg"
        elif sec_rva < 0x150a0000: sec_name = ".rr4"
        elif sec_rva < 0x150c6000: sec_name = ".rsrc"
        elif sec_rva < 0x150ce000: sec_name = ".reloc"
    
    flags = []
    if qt: flags.append("Qt")
    if dll: flags.append("DLL")
    print(f"  0x{base:016x} size=0x{size:08x} ({size/1048576:5.1f}MB) prot=0x{prot:x} sec={sec_name:10s} strings={cnt:4d} {' '.join(flags)}")

# For the most interesting region, dump all strings
print(f"\n=== Dumping strings from .pkg region ===")
for base, size, prot, cnt, qt, dll in interesting_regions:
    if qt or dll or cnt > 50:
        # Read more data
        read_size = min(size, 0x400000)  # 4MB
        buf = (ctypes.c_ubyte * read_size)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(base), buf, read_size, ctypes.byref(n))
        if ok and n.value > 0:
            data = bytes(buf[:n.value])
            strings = re.findall(rb'[\x20-\x7e]{12,}', data)
            print(f"\nRegion 0x{base:x} ({len(data)/1048576:.1f}MB, {len(strings)} strings):")
            for s in strings[:50]:
                print(f"  {s.decode('ascii','replace')[:120]}")
            
            # Also look for UTF-16LE
            # Quick check: look for wide char strings
            utf16 = []
            i = 0
            while i < len(data) - 4:
                if data[i+1] == 0 and 0x20 <= data[i] <= 0x7e:
                    j = i
                    chars = []
                    while j < len(data) - 1 and len(chars) < 200:
                        lo = data[j]
                        hi = data[j+1]
                        if hi == 0 and 0x20 <= lo <= 0x7e:
                            chars.append(chr(lo))
                            j += 2
                        elif hi > 0:
                            code = lo | (hi << 8)
                            if code >= 0x4e00:
                                chars.append(chr(code))
                                j += 2
                            else:
                                break
                        else:
                            break
                    if len(chars) >= 8:
                        s = ''.join(chars)
                        if any(c.isalpha() for c in s):
                            utf16.append((i, s))
                    i = j + 2
                else:
                    i += 1
            
            if utf16:
                print(f"  UTF-16LE strings ({len(utf16)}):")
                for off, s in utf16[:30]:
                    print(f"    0x{off:06x}: {s[:120]}")
            
            if len(strings) > 50:
                break  # Only dump one region

CH(h)
print("\nDONE")
