"""Full bypass + dump pipeline:
1. Rename window titles to avoid SProtect anti-debug
2. Launch AxonSkin_v4.1_asInvoker.exe
3. Watch for axonlogin.dll in %TEMP% and replace with patched version
4. Wait for main program to load (with decrypted .text)
5. Dump the process memory
6. Save dump for IDA analysis"""
import subprocess, os, sys, time, shutil, ctypes, ctypes.wintypes as w, json, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re"
PATCHED_DLL = os.path.join(WORK, "plaintext", "axonlogin_patched.dll")
EXE = os.path.join(WORK, "unpack", "AxonSkin_v4.1_asInvoker.exe")
TEMP = os.environ.get('TEMP', r'C:\Users\26346\AppData\Local\Temp')
TARGET_DLL = os.path.join(TEMP, "axonlogin.dll")
OUT_DIR = os.path.join(WORK, "unpack6")
os.makedirs(OUT_DIR, exist_ok=True)

# Step 1: Rename windows
print("[1] Renaming window titles...")
rename_script = os.path.join(WORK, "scripts", "rename_windows.py")
subprocess.run([sys.executable, rename_script], capture_output=True, timeout=10)
print("    Done")

# Step 2: Launch the patched exe
print(f"[2] Launching: {EXE}")
# Pre-copy patched DLL name so we know the size
patched_size = os.path.getsize(PATCHED_DLL)

# Start the process
proc = subprocess.Popen([EXE], creationflags=0x00000008)  # DETACHED_PROCESS
pid = proc.pid
print(f"    PID: {pid}")

# Step 3: Watch for axonlogin.dll and replace it
print(f"[3] Watching for {TARGET_DLL}...")
replaced = False
for i in range(120):  # 60 seconds
    if os.path.exists(TARGET_DLL):
        cur_size = os.path.getsize(TARGET_DLL)
        print(f"    Found! size={cur_size} (patched={patched_size})")
        if cur_size != patched_size:
            # This is the original - replace it
            try:
                # Try direct copy
                shutil.copy2(PATCHED_DLL, TARGET_DLL)
                print(f"[+] Replaced original DLL with patched version!")
                replaced = True
                break
            except PermissionError:
                # File is locked - try rename trick
                try:
                    backup = TARGET_DLL + ".orig"
                    os.rename(TARGET_DLL, backup)
                    shutil.copy2(PATCHED_DLL, TARGET_DLL)
                    print(f"[+] Replaced via rename trick!")
                    replaced = True
                    break
                except Exception as e:
                    print(f"    Rename failed: {e}, retrying...")
        else:
            # Already same size - check if it's already patched
            print(f"    Same size - might be already patched or different version")
            # Check the patch bytes
            with open(TARGET_DLL, 'rb') as f:
                f.seek(0x867E)
                check = f.read(5)
            if check == b'\x90\x90\x90\x90\x90':
                print(f"[+] Already patched!")
                replaced = True
                break
            else:
                # Original with same size - replace
                try:
                    shutil.copy2(PATCHED_DLL, TARGET_DLL)
                    print(f"[+] Replaced same-size DLL!")
                    replaced = True
                    break
                except PermissionError:
                    try:
                        os.rename(TARGET_DLL, TARGET_DLL + ".orig")
                        shutil.copy2(PATCHED_DLL, TARGET_DLL)
                        print(f"[+] Replaced via rename!")
                        replaced = True
                        break
                    except Exception as e:
                        print(f"    Failed: {e}")
    time.sleep(0.5)

if not replaced:
    print("[-] Could not replace DLL in time")

# Step 4: Wait for the main program to load
print("[4] Waiting for main program to load (15 seconds)...")
time.sleep(15)

# Step 5: Find and dump the process
print("[5] Looking for AxonSkin process...")
import ctypes
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

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

# Find process
target_pid = None
# Check all windows with "Axon" in title
import subprocess as sp
result = sp.run(['tasklist', '/fi', 'IMAGENAME eq AxonSkin_v4.1_asInvoker.exe', '/fo', 'csv'], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if 'AxonSkin' in line:
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 2:
            try:
                target_pid = int(parts[1])
                print(f"    Found PID: {target_pid}")
            except:
                pass

if not target_pid:
    # Try the original exe name
    result = sp.run(['tasklist', '/fi', 'IMAGENAME eq AxonSkin v4.1.exe', '/fo', 'csv'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'AxonSkin' in line:
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                try:
                    target_pid = int(parts[1])
                    print(f"    Found PID (original): {target_pid}")
                except:
                    pass

if not target_pid:
    # Use the launched pid
    target_pid = pid
    print(f"    Using launched PID: {target_pid}")

h = OP(PROCESS_ALL_ACCESS, False, target_pid)
if not h:
    err = ctypes.get_last_error()
    print(f"[-] OpenProcess failed (err={err}). Trying with lower access...")
    h = OP(0x0410, False, target_pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

if h:
    print(f"[+] OpenProcess OK (handle={h})")
    # Query regions
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

    print(f"    Committed regions: {len(regions)}")
    
    # Dump each region
    total = 0
    exec_regions = []
    for (base, size, prot, typ) in regions:
        buf = bytearray()
        cur = base
        end = base + size
        while cur < end:
            chunk = min(0x10000, end - cur)
            tmp = (ctypes.c_ubyte * chunk)()
            n = ctypes.c_size_t(0)
            ok = RPM(h, ctypes.c_void_p(cur), tmp, chunk, ctypes.byref(n))
            if ok and n.value > 0:
                buf.extend(tmp[:n.value])
            else:
                buf.extend(b'\x00' * chunk)
            cur += chunk
        data = bytes(buf)
        if any(b != 0 for b in data[:min(len(data), 0x10000)]):
            fname = f"r_{base:016x}_{size:08x}_p{prot:x}_t{typ:x}.bin"
            with open(os.path.join(OUT_DIR, fname), "wb") as f:
                f.write(data)
            total += len(data)
            if prot == 0x20 and size > 0x100000:  # EXECUTE + large
                exec_regions.append((base, size, fname))
                print(f"    *** EXECUTE 0x{base:x} size=0x{size:x} ({size/1048576:.1f}MB) -> {fname}")
    
    # Save manifest
    manifest = [{"base": b, "size": s, "prot": p, "type": t, "file": f"r_{b:016x}_{s:08x}_p{p:x}_t{t:x}.bin"} for (b, s, p, t) in regions]
    with open(os.path.join(OUT_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Saved {len(regions)} regions, {total/1048576:.1f}MB")
    if exec_regions:
        print(f"[+] Found {len(exec_regions)} EXECUTE regions (decrypted code!)")
    CH(h)
else:
    print(f"[-] Cannot open process (pid={target_pid})")

# Also try minidump
try:
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
    MiniDumpWriteDump.argtypes = [w.HANDLE, w.DWORD, w.HANDLE, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    MiniDumpWriteDump.restype = w.BOOL
    MiniDumpWithFullMemory = 0x2
    CreateFileW = k32.CreateFileW
    CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    CreateFileW.restype = w.HANDLE
    
    md_path = os.path.join(OUT_DIR, "full.dmp")
    h2 = OP(0x1F0FFF, False, target_pid)
    if h2:
        hf = CreateFileW(md_path, 0x60000000, 0x3, None, 2, 0, None)
        if hf:
            ok = MiniDumpWriteDump(h2, target_pid, hf, MiniDumpWithFullMemory, None, None, None)
            CH(hf)
            print(f"[+] Minidump: ok={ok} size={os.path.getsize(md_path)/1048576:.1f}MB")
        CH(h2)
except Exception as e:
    print(f"[-] Minidump failed: {e}")

print("[6] DONE")
