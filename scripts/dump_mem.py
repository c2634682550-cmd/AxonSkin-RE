"""
Runtime memory dumper for packed PE.
- CreateProcess suspended
- resume, let unpacker run (sleep)
- suspend all threads
- VirtualQueryEx enumerate committed, readable, non-image regions
- ReadProcessMemory dump
- also dump a full minidump
- locate the original .text region (ImageBase+0x1000) and reconstruct PE
"""
import ctypes, ctypes.wintypes as w, struct, os, sys, time

TARGET = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack\AxonSkin_v4.1_asInvoker.exe"
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
os.makedirs(OUT, exist_ok=True)

# --- Win32 constants ---
PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x4
CREATE_NEW_CONSOLE = 0x10
THREAD_SUSPEND_RESUME = 0x0002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb",w.DWORD),("lpReserved",w.LPWSTR),("lpDesktop",w.LPWSTR),
        ("lpTitle",w.LPWSTR),("dwX",w.DWORD),("dwY",w.DWORD),("dwXSize",w.DWORD),
        ("dwYSize",w.DWORD),("dwXCountChars",w.DWORD),("dwYCountChars",w.DWORD),
        ("dwFillAttribute",w.DWORD),("dwFlags",w.DWORD),("wShowWindow",w.WORD),
        ("cbReserved2",w.WORD),("lpReserved2",ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput",w.HANDLE),("hStdOutput",w.HANDLE),("hStdError",w.HANDLE)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",w.HANDLE),("hThread",w.HANDLE),
        ("dwProcessId",w.DWORD),("dwThreadId",w.DWORD)]
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_=[("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
        ("AllocationProtect",w.DWORD),("RegionSize",ctypes.c_size_t),
        ("State",w.DWORD),("Protect",w.DWORD),("Type",w.DWORD)]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

CreateProcessW = k32.CreateProcessW
CreateProcessW.restype = w.BOOL
CreateProcessW.argtypes = [w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,
    ctypes.c_void_p,w.LPCWSTR,ctypes.POINTER(STARTUPINFOW),ctypes.POINTER(PROCESS_INFORMATION)]
ResumeThread = k32.ResumeThread; ResumeThread.argtypes=[w.HANDLE]; ResumeThread.restype=w.DWORD
SuspendThread = k32.SuspendThread; SuspendThread.argtypes=[w.HANDLE]; SuspendThread.restype=w.DWORD
WaitForSingleObject = k32.WaitForSingleObject; WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]
WaitForSingleObject.restype=w.DWORD
CloseHandle = k32.CloseHandle; CloseHandle.argtypes=[w.HANDLE]; CloseHandle.restype=w.BOOL
VirtualQueryEx = k32.VirtualQueryEx
VirtualQueryEx.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.POINTER(MEMORY_BASIC_INFORMATION),ctypes.c_size_t]
VirtualQueryEx.restype=ctypes.c_size_t
ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype=w.BOOL
OpenThread = k32.OpenThread; OpenThread.argtypes=[w.DWORD,w.BOOL,w.DWORD]; OpenThread.restype=w.HANDLE
Thread32First = k32.Thread32First
Thread32Next = k32.Thread32Next
class THREADENTRY32(ctypes.Structure):
    _fields_=[("dwSize",w.DWORD),("cntUsage",w.DWORD),("th32ThreadID",w.DWORD),
        ("th32OwnerProcessID",w.DWORD),("tpBasePri",w.LONG),("tpDeltaPri",w.LONG),
        ("dwFlags",w.DWORD)]
CreateToolhelp32Snapshot = k32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]; CreateToolhelp32Snapshot.restype=w.HANDLE
TH32CS_SNAPTHREAD = 0x4
GetExitCodeProcess = k32.GetExitCodeProcess; GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]
GetModuleFileNameExW = psapi.GetModuleFileNameExW
GetModuleFileNameExW.argtypes=[w.HANDLE,w.HANDLE,w.LPWSTR,w.DWORD]
EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.argtypes=[w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,ctypes.POINTER(w.DWORD)]
EnumProcessModules.restype=w.BOOL
GetModuleBaseNameW = psapi.GetModuleBaseNameW
GetModuleBaseNameW.argtypes=[w.HANDLE,w.HANDLE,w.LPWSTR,w.DWORD]; GetModuleBaseNameW.restype=w.DWORD

MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
MiniDumpWriteDump.argtypes=[w.HANDLE,w.DWORD,w.HANDLE,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
MiniDumpWriteDump.restype=w.BOOL
MiniDumpWithFullMemory = 0x2

def dump_regions(pid, outdir, image_base=None):
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    total = 0
    # enumerate entire 64-bit address space in chunks
    addr = 0
    step_fail = 0
    while addr < (1<<48):
        r = VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0:
            addr += 0x1000
            step_fail += 1
            if step_fail > 0x100000: break
            continue
        step_fail = 0
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if mbi.State == MEM_COMMIT and mbi.Protect not in (0,) and not (mbi.Protect & 0x100):
            # readable & not PAGE_NOACCESS (0x01) and not guard (0x100)
            if mbi.Type == MEM_PRIVATE or mbi.Type == MEM_MAPPED or mbi.Type == MEM_IMAGE:
                regions.append((base, size, mbi.Protect, mbi.Type, mbi.AllocationBase))
        addr = base + size
        if addr <= (mbi.BaseAddress or 0): addr = (mbi.BaseAddress or 0) + 0x1000

    print(f"committed regions: {len(regions)}")
    # dump each region
    manifest = []
    for (base,size,prot,typ,allocbase) in regions:
        try:
            buf = (ctypes.c_ubyte*size)()
            nread = ctypes.c_size_t(0)
            ok = ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(nread))
            data = bytes(buf[:nread.value]) if ok else b""
        except Exception as e:
            data = b""
        if data:
            fname = f"r_{base:016x}_{size:08x}_p{prot:x}_t{typ:x}.bin"
            with open(os.path.join(outdir, fname),"wb") as f:
                f.write(data)
            manifest.append({"base":base,"size":size,"prot":prot,"type":typ,"file":fname,"nread":len(data)})
            total += len(data)
    with open(os.path.join(outdir,"manifest.json"),"w") as f:
        import json
        json.dump(manifest, f, indent=2)
    print(f"dumped {len(manifest)} regions, {total/1048576:.1f} MB total")
    # minidump
    mdpath = os.path.join(outdir, "full.dmp")
    with open(mdpath,"wb") as dummy: pass
    hFile = k32.CreateFileW(mdpath, 0x40000000|0x20000000, 0x3, None, 2, 0, None)
    ok = MiniDumpWriteDump(h, pid, hFile, MiniDumpWithFullMemory, None, None, None)
    k32.CloseHandle(hFile)
    print(f"minidump: {ok} -> {mdpath} ({os.path.getsize(mdpath)/1048576:.1f} MB)")
    CloseHandle(h)
    return manifest

def main():
    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{TARGET}"'
    print(f"CreateProcess suspended: {TARGET}")
    ok = CreateProcessW(None, ctypes.create_unicode_buffer(cmd), None, None, False,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print(f"CreateProcess failed: {ctypes.get_last_error()}")
        return
    print(f"pid={pi.dwProcessId} tid={pi.dwThreadId}")
    # resume
    prev = ResumeThread(pi.hThread)
    print(f"resumed (prev suspend count={prev})")
    # let it unpack
    for t in (2,3,5):
        time.sleep(t)
        # check alive
        ec = w.DWORD(0)
        still = GetExitCodeProcess(pi.hProcess, ctypes.byref(ec))
        if still and ec.value != 0x103:
            print(f"process exited with code {ec.value:#x} before dump")
            break
    # suspend all threads
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32(); te.dwSize = ctypes.sizeof(te)
    nthreads=0
    if Thread32First(snap, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pi.dwProcessId:
                th = OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                if th:
                    SuspendThread(th); CloseHandle(th); nthreads+=1
            if not Thread32Next(snap, ctypes.byref(te)): break
    CloseHandle(snap)
    print(f"suspended {nthreads} threads")
    # dump
    manifest = dump_regions(pi.dwProcessId, OUT)
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess)
    print("DONE")

if __name__ == "__main__":
    main()
