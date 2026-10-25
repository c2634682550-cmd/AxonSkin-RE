"""Parse axon_regions/index.json, find the main module image (the big EXECUTE regions),
reconstruct the unpacked PE, and verify it has real Qt code.
"""
import json, os, struct

REG = r"C:\Users\26346\AppData\Local\Temp\axon_regions"
with open(os.path.join(REG,"index.json")) as f:
    idx = json.load(f)

regions = idx["regions"]
print(f"pid={idx.get('pid')}  total regions={len(regions)}")

# find MZ header
mz_regs = []
for r in regions:
    addr = r["addr"]
    if addr < 0x800000000000:  # user space
        data = open(os.path.join(REG,r["file"]),"rb").read(64)
        if data[:2]==b"MZ":
            mz_regs.append((r, data))
            if len(mz_regs) <= 8:
                print(f"  MZ region addr=0x{addr:x} size={r['size']} prot={r['protect']} {r['file']}")

print(f"\ntotal MZ regions: {len(mz_regs)}")

# The main module: a small header region (prot=2, 0x1000) followed by big EXECUTE
# Find header region whose next region is big exec
main = None
for i,(r,d) in enumerate(mz_regs):
    if r["protect"]==2 and r["size"]<=0x2000:
        e_lfanew = struct.unpack_from("<I",d,0x3C)[0]
        if e_lfanew+4 < len(d) and d[e_lfanew:e_lfanew+4]==b"PE\x00\x00":
            # look for following big exec region in the full list
            for r2 in regions:
                if r2["addr"]==r["addr"]+r["size"] and r2["protect"]==0x20 and r2["size"]>0x1000000:
                    main = r
                    print(f"\nMAIN MODULE: header at 0x{r['addr']:x} ({r['file']}), followed by exec 0x{r2['addr']:x} size={r2['size']}")
                    break
        if main: break

if not main:
    print("no main module found, trying first MZ")
    main = mz_regs[0][0]

# parse PE header
hdr = open(os.path.join(REG, main["file"]),"rb").read()
e_lfanew = struct.unpack_from("<I",hdr,0x3C)[0]
pe = e_lfanew
numsec = struct.unpack_from("<H",hdr,pe+6)[0]
szopt = struct.unpack_from("<H",hdr,pe+20)[0]
opt = hdr[pe+24:pe+24+szopt]
magic = struct.unpack_from("<H",opt,0)[0]
ep = struct.unpack_from("<I",opt,16)[0]
sizeimg = struct.unpack_from("<I",opt,56)[0]
print(f"PE numsec={numsec} magic=0x{magic:x} EP=0x{ep:x} SizeOfImage=0x{sizeimg:x}")
sec_off = pe+24+szopt
secs=[]
for i in range(numsec):
    s=hdr[sec_off+i*40:sec_off+i*40+40]
    nm=s[:8].rstrip(b"\x00").decode("latin1","replace")
    vs=struct.unpack_from("<I",s,8)[0]; va=struct.unpack_from("<I",s,12)[0]
    print(f"  {nm:10} VA=0x{va:08x} VS=0x{vs:08x}")
    secs.append((nm,va,vs))

# Build address->region map for stitching
regmap = {}
for r in regions:
    regmap[r["addr"]] = r

# read full image
def read_mem(addr, length):
    out = bytearray(length)
    for r in regions:
        rb=r["addr"]; rs=r["size"]; re_=rb+rs
        if re_<=addr or rb>=addr+length: continue
        start=max(addr,rb); stop=min(addr+length,re_)
        data=open(os.path.join(REG,r["file"]),"rb").read()
        doff=start-rb
        dlen=min(stop-start, len(data)-doff)
        if dlen>0:
            out[start-addr:start-addr+dlen]=data[doff:doff+dlen]
    return bytes(out)

print(f"\nreading image 0x{sizeimg:x} from 0x{main['addr']:x}...")
image = read_mem(main["addr"], sizeimg)
print(f"image size 0x{len(image):x}")

# check .text (first code section)
for (nm,va,vs) in secs:
    chunk = image[va:va+min(vs,0x40)]
    nz = sum(1 for b in chunk if b!=0)
    print(f"  {nm:10} VA=0x{va:08x} head={chunk.hex(' ')} nonzero={nz}/{len(chunk)}")

# count prologues in .text
for (nm,va,vs) in secs:
    if nm in (".text",".a1",".rr4",".pkg"):
        txt = image[va:va+vs]
        p1 = txt.count(bytes([0x48,0x89,0x5c,0x24]))
        calls = txt.count(b"\xe8")
        retn = txt.count(b"\xc3")
        print(f"  {nm}: prologue4889={p1} calls={calls} retn={retn} (first 32: {txt[:32].hex(' ')})")

# save reconstructed
outpath = os.path.join(REG, "..", "axon_unpacked_from_regions.exe")
# rebuild with proper raw layout
falign=0x200
def al(v,a): return (v+a-1)&~(a-1)
hdr_end = sec_off + numsec*40
hsz = al(hdr_end, falign)
out = bytearray(hsz)
out[:hdr_end] = image[:hdr_end]
cur=hsz
newsecs=[]
for (nm,va,vs,_,_,_) in [(nm,va,vs,0,0,0) for (nm,va,vs) in secs]:
    sd = image[va:va+vs]
    rawsz = al(len(sd), falign)
    newsecs.append((nm,va,vs,rawsz,cur,sd))
    cur += rawsz
# rewrite section table
for i,(nm,va,vs,rawsz,rawptr,sd) in enumerate(newsecs):
    s=bytearray(40); s[0:8]=nm.encode("latin1")[:8].ljust(8,b"\x00")
    struct.pack_into("<I",s,8,vs); struct.pack_into("<I",s,12,va)
    struct.pack_into("<I",s,16,rawsz); struct.pack_into("<I",s,20,rawptr)
    out[sec_off+i*40:sec_off+i*40+40]=s
out.extend(b"\x00"*(cur-len(out)))
for (nm,va,vs,rawsz,rawptr,sd) in newsecs:
    out[rawptr:rawptr+len(sd)]=sd
with open(outpath,"wb") as f: f.write(out)
print(f"\nsaved reconstructed -> {outpath} ({len(out)/1048576:.1f}MB)")
