"""
Re-dump with longer wait + capture thread contexts (RIP) to find where code executes.
"""
import ctypes, ctypes.wintypes as w, struct, os, json, time

TARGET = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack\AxonSkin_v4.1_asInvoker.exe"
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack2"
os.makedirs(OUT, exist_ok=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x4
CREATE_NEW_CONSOLE = 0x10
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb",w.DWORD),("lpReserved",w.LPWSTR),("lpDesktop",w.LPWSTR),
        ("lpTitle",w.LPWSTR),("dwX",w.DWORD),("dwY",w.DWORD),("dwXSize",w.DWORD),
        ("dwYSize",w.DWORD),("dwXCountChars",w.DWORD),("dwYCountChars",w.DWORD),
        ("dwFillAttribute",w.DWORD),("dwFlags",w.DWORD),("wShowWindow",w.WORD),
        ("cbReserved2",w.WORD),("lpReserved2",ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput",w.HANDLE),("hStdOutput",w.HANDLE),("hStdError",w.HANDLE)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",w.HANDLE),("hThread",w.HANDLE),("dwProcessId",w.DWORD),("dwThreadId",w.DWORD)]
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_=[("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
        ("AllocationProtect",w.DWORD),("RegionSize",ctypes.c_size_t),
        ("State",w.DWORD),("Protect",w.DWORD),("Type",w.DWORD)]

# CONTEXT for x64
class M128A(ctypes.Structure):
    _fields_=[("Low",ctypes.c_ulonglong),("High",ctypes.c_longlong)]
class CONTEXT(ctypes.Structure):
    _fields_=[
        ("P1Home",ctypes.c_ulonglong),("P2Home",ctypes.c_ulonglong),("P3Home",ctypes.c_ulonglong),
        ("P4Home",ctypes.c_ulonglong),("P5Home",ctypes.c_ulonglong),("P6Home",ctypes.c_ulonglong),
        ("ContextFlags",w.DWORD),("MxCsr",w.DWORD),
        ("SegmentEs",w.WORD),("SegmentCs",w.WORD),("SegmentSs",w.WORD),("SegmentDs",w.WORD),("SegmentFs",w.WORD),("SegmentGs",w.WORD),
        ("EFlags",w.DWORD),
        ("Dr0",ctypes.c_ulonglong),("Dr1",ctypes.c_ulonglong),("Dr2",ctypes.c_ulonglong),
        ("Dr3",ctypes.c_ulonglong),("Dr6",ctypes.c_ulonglong),("Dr7",ctypes.c_ulonglong),
        ("Rax",ctypes.c_ulonglong),("Rcx",ctypes.c_ulonglong),("Rdx",ctypes.c_ulonglong),
        ("Rbx",ctypes.c_ulonglong),("Rsp",ctypes.c_ulonglong),("Rbp",ctypes.c_ulonglong),
        ("Rsi",ctypes.c_ulonglong),("Rdi",ctypes.c_ulonglong),("R8",ctypes.c_ulonglong),
        ("R9",ctypes.c_ulonglong),("R10",ctypes.c_ulonglong),("R11",ctypes.c_ulonglong),
        ("R12",ctypes.c_ulonglong),("R13",ctypes.c_ulonglong),("R14",ctypes.c_ulonglong),
        ("R15",ctypes.c_ulonglong),("Rip",ctypes.c_ulonglong),
        ("FltSave",ctypes.c_ubyte*512),
        ("VectorRegister",M128A*26),("VectorControl",ctypes.c_ulonglong),
        ("DebugControl",ctypes.c_ulonglong),("LastBranchToRip",ctypes.c_ulonglong),
        ("LastBranchFromRip",ctypes.c_ulonglong),("LastExceptionToRip",ctypes.c_ulonglong),
        ("LastExceptionFromRip",ctypes.c_ulonglong),
    ]

class THREADENTRY32(ctypes.Structure):
    _fields_=[("dwSize",w.DWORD),("cntUsage",w.DWORD),("th32ThreadID",w.DWORD),
        ("th32OwnerProcessID",w.DWORD),("tpBasePri",w.LONG),("tpDeltaPri",w.LONG),("dwFlags",w.DWORD)]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

CreateProcessW = k32.CreateProcessW
CreateProcessW.restype = w.BOOL
CreateProcessW.argtypes = [w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,ctypes.c_void_p,w.LPCWSTR,ctypes.POINTER(STARTUPINFOW),ctypes.POINTER(PROCESS_INFORMATION)]
ResumeThread = k32.ResumeThread; ResumeThread.argtypes=[w.HANDLE]; ResumeThread.restype=w.DWORD
SuspendThread = k32.SuspendThread; SuspendThread.argtypes=[w.HANDLE]; SuspendThread.restype=w.DWORD
WaitForSingleObject = k32.WaitForSingleObject; WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]; WaitForSingleObject.restype=w.DWORD
CloseHandle = k32.CloseHandle
VirtualQueryEx = k32.VirtualQueryEx
VirtualQueryEx.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.POINTER(MEMORY_BASIC_INFORMATION),ctypes.c_size_t]
VirtualQueryEx.restype=ctypes.c_size_t
ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype=w.BOOL
OpenThread = k32.OpenThread; OpenThread.argtypes=[w.DWORD,w.BOOL,w.DWORD]; OpenThread.restype=w.HANDLE
GetThreadContext = k32.GetThreadContext; GetThreadContext.argtypes=[w.HANDLE,ctypes.POINTER(CONTEXT)]; GetThreadContext.restype=w.BOOL
Thread32First = k32.Thread32First; Thread32Next = k32.Thread32Next
CreateToolhelp32Snapshot = k32.CreateToolhelp32Snapshot; CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]; CreateToolhelp32Snapshot.restype=w.HANDLE
TH32CS_SNAPTHREAD = 0x4
CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = 0x100001

# minidump
dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
MiniDumpWriteDump.argtypes=[w.HANDLE,w.DWORD,w.HANDLE,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
MiniDumpWriteDump.restype=w.BOOL
MiniDumpWithFullMemory = 0x2

# find window for the process
user32 = ctypes.WinDLL("user32", use_last_error=True)
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes=[w.HWND, ctypes.POINTER(w.DWORD)]
GetWindowThreadProcessId.restype=w.DWORD
GetWindowTextW = user32.GetWindowTextW; GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,w.INT]; GetWindowTextW.restype=w.INT
IsWindowVisible = user32.IsWindowVisible; IsWindowVisible.argtypes=[w.HANDLE]; IsWindowVisible.restype=w.BOOL

def dump_regions(pid, outdir):
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h: print(f"OpenProcess failed: {ctypes.get_last_error()}"); return None
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < (1<<48):
        r = VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0:
            addr += 0x1000; continue
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if mbi.State == MEM_COMMIT and mbi.Protect not in (0,0x01) and not (mbi.Protect & 0x100):
            regions.append((base, size, mbi.Protect, mbi.Type, mbi.AllocationBase))
        addr = base + size
        if addr <= (mbi.BaseAddress or 0): addr = (mbi.BaseAddress or 0) + 0x1000

    manifest = []
    total = 0
    for (base,size,prot,typ,allocbase) in regions:
        buf = (ctypes.c_ubyte*size)()
        nread = ctypes.c_size_t(0)
        ok = ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(nread))
        data = bytes(buf[:nread.value]) if ok else b""
        if data:
            fname = f"r_{base:016x}_{size:08x}_p{prot:x}_t{typ:x}.bin"
            with open(os.path.join(outdir,fname),"wb") as f: f.write(data)
            manifest.append({"base":base,"size":size,"prot":prot,"type":typ,"file":fname,"nread":len(data)})
            total += len(data)
    with open(os.path.join(outdir,"manifest.json"),"w") as f:
        json.dump(manifest,f,indent=2)
    # minidump
    mdpath = os.path.join(outdir,"full.dmp")
    hFile = k32.CreateFileW(mdpath,0x40000000|0x20000000,0x3,None,2,0,None)
    MiniDumpWriteDump(h,pid,hFile,MiniDumpWithFullMemory,None,None,None)
    k32.CloseHandle(hFile)
    print(f"dumped {len(manifest)} regions, {total/1048576:.1f}MB; minidump {os.path.getsize(mdpath)/1048576:.1f}MB")
    CloseHandle(h)
    return manifest

def get_threads(pid):
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32(); te.dwSize = ctypes.sizeof(te)
    threads = []
    if Thread32First(snap, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pid:
                threads.append(te.th32ThreadID)
            if not Thread32Next(snap, ctypes.byref(te)): break
    CloseHandle(snap)
    return threads

def main():
    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{TARGET}"'
    print(f"CreateProcess suspended...")
    ok = CreateProcessW(None, ctypes.create_unicode_buffer(cmd), None, None, False,
        CREATE_SUSPENDED|CREATE_NEW_CONSOLE, None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok: print(f"CreateProcess failed: {ctypes.get_last_error()}"); return
    print(f"pid={pi.dwProcessId}")
    ResumeThread(pi.hThread)
    print("resumed; waiting 30s for full unpack...")
    time.sleep(30)
    # check alive
    ec = w.DWORD(0)
    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(ec))
    if ec.value != 0x103:
        print(f"process exited: {ec.value:#x}"); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return
    # check for windows
    found_wins = []
    def cb(hwnd, lp):
        wpid = w.DWORD(0)
        GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pi.dwProcessId:
            buf = ctypes.create_unicode_buffer(256)
            GetWindowTextW(hwnd, buf, 256)
            vis = IsWindowVisible(hwnd)
            found_wins.append((hwnd, buf.value, bool(vis)))
        return True
    EnumWindows(EnumWindowsProc(cb), 0)
    if found_wins:
        print(f"windows: {len(found_wins)}")
        for hwnd, title, vis in found_wins[:5]:
            print(f"  hwnd={hwnd} title='{title}' visible={vis}")
    else:
        print("no windows found")

    # suspend all threads
    tids = get_threads(pi.dwProcessId)
    print(f"threads: {len(tids)}")
    for tid in tids:
        th = OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION, False, tid)
        if th:
            SuspendThread(th)
            # get context
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_AMD64 | CONTEXT_CONTROL
            if GetThreadContext(th, ctypes.byref(ctx)):
                print(f"  tid={tid} RIP=0x{ctx.Rip:x} RSP=0x{ctx.Rsp:x}")
            CloseHandle(th)
    print("dumping...")
    manifest = dump_regions(pi.dwProcessId, OUT)
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess)
    print("DONE")

if __name__=="__main__":
    main()
