"""Find the main Axon module: the MZ header at 0x7ff7afb90000 (reg_055) + big exec next to it.
Also identify the 117MB region."""
import json, os, struct
REG = r"C:\Users\26346\AppData\Local\Temp\axon_regions"
with open(os.path.join(REG,"index.json")) as f:
    idx = json.load(f)
regions = idx["regions"]

# sort by addr
regions.sort(key=lambda r: r["addr"])

# print all regions sorted with nonzero/entropy, flag big+exec
print("=== sorted regions (big/exec/high-entropy) ===")
for r in regions:
    a=r["addr"]; s=r["size"]; p=r["protect"]; nz=r.get("nonzero",0); en=r.get("entropy",0)
    # only interesting ones
    if s > 0x100000 or (p==0x20 and s>0x10000) or (nz>0.5 and en>5 and s>0x100000):
        print(f"  addr=0x{a:x} size=0x{s:x}({s/1048576:.1f}MB) prot=0x{p:x} nz={nz:.2f} ent={en:.1f} {r['file']}")

# find reg_055 (0x7ff7afb90000) header
print("\n=== reg_055 (0x7ff7afb90000) header ===")
h = open(os.path.join(REG,"reg_055_7ff7afb90000.bin"),"rb").read(64)
print(f"  MZ={h[:2]==b'MZ'}  e_lfanew=0x{struct.unpack_from('<I',h,0x3C)[0]:x}")
ef = struct.unpack_from("<I",h,0x3C)[0]
# need more bytes; region is 0x1000
full = open(os.path.join(REG,"reg_055_7ff7afb90000.bin"),"rb").read()
print(f"  PE sig: {full[ef:ef+4]}")
numsec = struct.unpack_from("<H",full,ef+6)[0]
szopt = struct.unpack_from("<H",full,ef+20)[0]
opt = full[ef+24:ef+24+szopt]
ep = struct.unpack_from("<I",opt,16)[0]
imgbase = struct.unpack_from("<Q",opt,24)[0]
sizeimg = struct.unpack_from("<I",opt,56)[0]
print(f"  numsec={numsec} EP=0x{ep:x} ImageBase=0x{imgbase:x} SizeOfImage=0x{sizeimg:x}")
sec = ef+24+szopt
for i in range(numsec):
    s=full[sec+i*40:sec+i*40+40]
    nm=s[:8].rstrip(b"\x00").decode("latin1","replace")
    vs=struct.unpack_from("<I",s,8)[0]; va=struct.unpack_from("<I",s,12)[0]
    print(f"    {nm:10} VA=0x{va:08x} VS=0x{vs:08x}")

# Now look at the biggest region (117MB)
print("\n=== biggest regions ===")
for r in sorted(regions, key=lambda x:-x["size"])[:8]:
    print(f"  0x{r['addr']:x} size=0x{r['size']:x}({r['size']/1048576:.1f}MB) prot=0x{r['protect']:x} ent={r.get('entropy',0):.1f} {r['file']}")
    # check if it starts with MZ or has Qt strings
    d = open(os.path.join(REG,r["file"]),"rb").read(4096)
    print(f"    head: {d[:32].hex(' ')}")
    # ascii strings
    import re
    ss = re.findall(b"[\x20-\x7e]{6,}", d)
    print(f"    sample strings: {[s.decode('latin1','replace') for s in ss[:8]]}")
