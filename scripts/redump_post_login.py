"""Re-dump the running process (pid 54824) which has already passed login.
This should capture the decrypted .text section."""
import ctypes, ctypes.wintypes as w, sys, os, json, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"
os.makedirs(OUT, exist_ok=True)

PID = 54824  # The running AxonSkin process
main_base = 0x7ff78e700000  # Known from minidump module list

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
    err = ctypes.get_last_error()
    print(f"OpenProcess failed (err={err})")
    # Try lower access
    h = OP(0x1F0FFF, False, PID)
    if not h:
        h = OP(0x0410, False, PID)  # QUERY_INFORMATION | VM_READ

if not h:
    print("Cannot open process at all")
    sys.exit(1)

print(f"OpenProcess OK (handle={h})")

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
        regions.append((base, size, mbi.Protect, mbi.Type))
    addr = base + size
    if addr <= (mbi.BaseAddress or 0):
        addr = (mbi.BaseAddress or 0) + 0x1000

print(f"Committed regions: {len(regions)}")

# Find regions within the main module's .text range
text_start = main_base + 0x1000
text_end = main_base + 0x1000 + 0x0261380d
rdata_start = main_base + 0x2615000
rdata_end = main_base + 0x2615000 + 0x15ed084

print(f"\n.text: 0x{text_start:x} - 0x{text_end:x}")
print(f".rdata: 0x{rdata_start:x} - 0x{rdata_end:x}")

# Dump .text
text_data = bytearray()
for base, size, prot, typ in regions:
    if base < text_end and base + size > text_start:
        overlap_start = max(base, text_start)
        overlap_end = min(base + size, text_end)
        overlap_size = overlap_end - overlap_start
        print(f"  .text overlap: 0x{overlap_start:x} +0x{overlap_size:x} prot=0x{prot:x}")
        
        # Read this region
        buf = (ctypes.c_ubyte * overlap_size)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(overlap_start), buf, overlap_size, ctypes.byref(n))
        if ok and n.value > 0:
            text_data.extend(buf[:n.value])
        else:
            text_data.extend(b'\x00' * overlap_size)

# Check code quality
prologues = bytes(text_data[:0x100000]).count(b'\x48\x89\x5c\x24')
print(f"\n.text extracted: {len(text_data)/1048576:.1f}MB, prologues in 1st MB: {prologues}")

# Scan for prologues throughout
for i in range(0, len(text_data), 0x100000):
    chunk = bytes(text_data[i:i+0x100000])
    if len(chunk) == 0:
        break
    prol = chunk.count(b'\x48\x89\x5c\x24')
    if prol > 20:
        print(f"  offset 0x{i:x} ({i//1048576}MB): {prol} prologues")

# Save .text
out_text = os.path.join(OUT, "main_text.bin")
with open(out_text, "wb") as f:
    f.write(bytes(text_data))
print(f"Saved .text to {out_text}")

# Dump .rdata
rdata_data = bytearray()
for base, size, prot, typ in regions:
    if base < rdata_end and base + size > rdata_start:
        overlap_start = max(base, rdata_start)
        overlap_end = min(base + size, rdata_end)
        overlap_size = overlap_end - overlap_start
        buf = (ctypes.c_ubyte * overlap_size)()
        n = ctypes.c_size_t(0)
        ok = RPM(h, ctypes.c_void_p(overlap_start), buf, overlap_size, ctypes.byref(n))
        if ok and n.value > 0:
            rdata_data.extend(buf[:n.value])
        else:
            rdata_data.extend(b'\x00' * overlap_size)

out_rdata = os.path.join(OUT, "main_rdata.bin")
with open(out_rdata, "wb") as f:
    f.write(bytes(rdata_data))
print(f"Saved .rdata: {len(rdata_data)/1048576:.1f}MB to {out_rdata}")

# Check for strings in .rdata
ascii_strings = re.findall(rb'[\x20-\x7e]{12,}', bytes(rdata_data)[:0x200000])
print(f"ASCII strings in 1st 2MB: {len(ascii_strings)}")
for s in ascii_strings[:20]:
    print(f"  {s.decode('ascii','replace')[:100]}")

# Also try minidump with MiniDumpWriteDump
try:
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
    MiniDumpWriteDump.argtypes = [w.HANDLE, w.DWORD, w.HANDLE, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    MiniDumpWriteDump.restype = w.BOOL
    CreateFileW = k32.CreateFileW
    CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    CreateFileW.restype = w.HANDLE
    
    md_path = os.path.join(OUT, "post_login.dmp")
    hf = CreateFileW(md_path, 0x60000000, 0x3, None, 2, 0, None)
    if hf:
        ok = MiniDumpWriteDump(h, PID, hf, 0x2, None, None, None)  # FullMemory
        CH(hf)
        print(f"\nMinidump: ok={ok} size={os.path.getsize(md_path)/1048576:.1f}MB")
except Exception as e:
    print(f"Minidump failed: {e}")

# Save manifest
manifest = [{"base": b, "size": s, "prot": p, "type": t} for (b, s, p, t) in regions if s > 0x1000]
with open(os.path.join(OUT, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2)

CH(h)
print("DONE")
