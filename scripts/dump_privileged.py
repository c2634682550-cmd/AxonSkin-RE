"""Self-contained privileged memory dumper. Run elevated.
Dumps pid 44396 (or specified pid) full memory to axonskin_re/unpack5/"""
import ctypes, ctypes.wintypes as w, os, sys, json, struct

PID = int(sys.argv[1]) if len(sys.argv)>1 else 44396
OUT = rf"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack5"
os.makedirs(OUT, exist_ok=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

class MBI(ctypes.Structure):
    _fields_=[("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
        ("AllocationProtect",w.DWORD),("RegionSize",ctypes.c_size_t),
        ("State",w.DWORD),("Protect",w.DWORD),("Type",w.DWORD)]

VQ=k32.VirtualQueryEx; VQ.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.POINTER(MBI),ctypes.c_size_t]; VQ.restype=ctypes.c_size_t
RPM=k32.ReadProcessMemory; RPM.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]; RPM.restype=w.BOOL
OP=k32.OpenProcess; OP.argtypes=[w.DWORD,w.BOOL,w.DWORD]; OP.restype=w.HANDLE
CH=k32.CloseHandle; CH.argtypes=[w.HANDLE]
MDump=dbghelp.MiniDumpWriteDump; MDump.argtypes=[w.HANDLE,w.DWORD,w.HANDLE,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]; MDump.restype=w.BOOL
MiniDumpWithFullMemory=0x2
CF=k32.CreateFileW; CF.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE]; CF.restype=w.HANDLE

class THREADENTRY32(ctypes.Structure):
    _fields_=[("dwSize",w.DWORD),("cntUsage",w.DWORD),("th32ThreadID",w.DWORD),
        ("th32OwnerProcessID",w.DWORD),("tpBasePri",w.LONG),("tpDeltaPri",w.LONG),("dwFlags",w.DWORD)]
TS32=k32.CreateToolhelp32Snapshot; TS32.argtypes=[w.DWORD,w.DWORD]; TS32.restype=w.HANDLE
T32F=k32.Thread32First; T32F.argtypes=[w.HANDLE,ctypes.POINTER(THREADENTRY32)]; T32F.restype=w.BOOL
T32N=k32.Thread32Next; T32N.argtypes=[w.HANDLE,ctypes.POINTER(THREADENTRY32)]; T32N.restype=w.BOOL
OT=k32.OpenThread; OT.argtypes=[w.DWORD,w.BOOL,w.DWORD]; OT.restype=w.HANDLE
ST=k32.SuspendThread; ST.argtypes=[w.HANDLE]; ST.restype=w.DWORD

def get_threads(pid):
    snap=TS32(0x4,0); te=THREADENTRY32(); te.dwSize=ctypes.sizeof(te); out=[]
    if T32F(snap,ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID==pid: out.append(te.th32ThreadID)
            if not T32N(snap,ctypes.byref(te)): break
    CH(snap); return out

print(f"[dump] target pid={PID} out={OUT}")
h=OP(PROCESS_ALL_ACCESS,False,PID)
if not h:
    print(f"[dump] OpenProcess FAILED err={ctypes.get_last_error()}")
    sys.exit(1)
print(f"[dump] OpenProcess OK handle={h}")

# suspend threads
for tid in get_threads(PID):
    th=OT(0x0002,False,tid)
    if th:
        ST(th); CH(th)
print("[dump] threads suspended")

# query regions
regions=[]; addr=0; mbi=MBI(); fail=0
while addr<(1<<48):
    r=VQ(h,ctypes.c_void_p(addr),ctypes.byref(mbi),ctypes.sizeof(mbi))
    if r==0:
        addr+=0x1000; fail+=1
        if fail>0x200000: break
        continue
    fail=0
    base=mbi.BaseAddress or 0; size=mbi.RegionSize or 0
    if mbi.State==MEM_COMMIT and mbi.Protect not in (0,PAGE_NOACCESS) and not (mbi.Protect&PAGE_GUARD):
        regions.append((base,size,mbi.Protect,mbi.Type))
    addr=base+size
    if addr<=(mbi.BaseAddress or 0): addr=(mbi.BaseAddress or 0)+0x1000

print(f"[dump] committed regions: {len(regions)}")

# dump each region
manifest=[]; total=0; skipped=0
for (base,size,prot,typ) in regions:
    out=bytearray()
    cur=base; end=base+size
    while cur<end:
        chunk=min(0x10000,end-cur)
        buf=(ctypes.c_ubyte*chunk)(); n=ctypes.c_size_t(0)
        ok=RPM(h,ctypes.c_void_p(cur),buf,chunk,ctypes.byref(n))
        if ok and n.value>0:
            out.extend(buf[:n.value])
        else:
            for sub in range(0,chunk,0x1000):
                s2=min(0x1000,chunk-sub); buf2=(ctypes.c_ubyte*s2)(); n2=ctypes.c_size_t(0)
                ok2=RPM(h,ctypes.c_void_p(cur+sub),buf2,s2,ctypes.byref(n2))
                if ok2 and n2.value>0: out.extend(buf2[:n2.value])
                else: out.extend(b"\x00"*s2)
        cur+=chunk
    data=bytes(out)
    # check if it's the main module .text (base near 0x7ff633040000)
    if any(b!=0 for b in data[:min(len(data),0x10000)]):
        fname=f"r_{base:016x}_{size:08x}_p{prot:x}_t{typ:x}.bin"
        with open(os.path.join(OUT,fname),"wb") as f: f.write(data)
        manifest.append({"base":base,"size":size,"prot":prot,"type":typ,"file":fname})
        total+=len(data)
        # flag if this is .text (exec + large)
        if prot==0x20 and size>0x1000000:
            print(f"  *** EXECUTE REGION 0x{base:x} size=0x{size:x} ({size/1048576:.1f}MB) -> {fname}")
    else:
        skipped+=1

with open(os.path.join(OUT,"manifest.json"),"w") as f: json.dump(manifest,f,indent=2)
print(f"[dump] saved {len(manifest)} regions, {total/1048576:.1f}MB, skipped {skipped} zero")

# minidump
mdpath=os.path.join(OUT,"full.dmp")
hf=CF(mdpath,0x60000000,0x3,None,2,0,None)
if hf:
    ok=MDump(h,PID,hf,MiniDumpWithFullMemory,None,None,None)
    CH(hf)
    print(f"[dump] minidump ok={ok} {os.path.getsize(mdpath)/1048576:.1f}MB")
else:
    print(f"[dump] minidump CreateFile FAILED err={ctypes.get_last_error()}")

CH(h)
print("[dump] DONE")
