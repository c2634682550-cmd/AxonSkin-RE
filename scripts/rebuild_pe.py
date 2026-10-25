"""
Reconstruct the unpacked PE from memory regions.
- ImageBase = 0x140000000 (from optional header)
- Walk memory regions, find the one at ImageBase -> it's the mapped image base (unpacked)
- Rebuild a flat image (SizeOfImage) by stitching regions.
- Then split into sections using the on-disk section table? No - the in-memory section table
  has the unpacked layout. We read the PE header from memory at ImageBase, get the section
  table, and for each section copy RegionSize bytes from its VA.
- Output a reconstructed PE (as a memory dump / .bin) plus a .exe with rebuilt headers.
"""
import os, json, struct, ctypes

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
MANIFEST = os.path.join(OUT, "manifest.json")
IMAGE_BASE = 0x140000000

with open(MANIFEST) as f:
    manifest = json.load(f)

# index regions by base
regions = {r["base"]: r for r in manifest}
print(f"regions indexed: {len(regions)}")

# find region containing ImageBase
base_region = None
for r in manifest:
    if r["base"] <= IMAGE_BASE < r["base"] + r["size"]:
        base_region = r
        break
if not base_region:
    # try near
    print("No exact region at ImageBase; searching...")
    for r in sorted(manifest, key=lambda x: x["base"]):
        if abs(r["base"] - IMAGE_BASE) < 0x1000000:
            print(f"  near: 0x{r['base']:x} size 0x{r['size']:x} prot 0x{r['prot']:x} type 0x{r['type']:x}")
    raise SystemExit("no image-base region")

print(f"image base region: 0x{base_region['base']:x} size 0x{base_region['size']:x}")

def read_region(r):
    with open(os.path.join(OUT, r["file"]), "rb") as f:
        return f.read()

# We need a flat view. Build a sorted list of regions and stitch a contiguous image.
# Sort all regions, find the largest contiguous block starting at/around ImageBase.
allr = sorted(manifest, key=lambda x: x["base"])
# find start
start = None
for r in allr:
    if r["base"] == IMAGE_BASE:
        start = r; break
if not start:
    # pick the nearest region whose base <= IMAGE_BASE and spans it
    for r in allr:
        if r["base"] <= IMAGE_BASE < r["base"]+r["size"]:
            start = r; break
if not start:
    raise SystemExit("cannot locate start region")

print(f"start region 0x{start['base']:x} sz 0x{start['size']:x}")

# Stitch contiguous regions forward from start.base
stitched = bytearray()
cur = start["base"]
i = next(idx for idx, r in enumerate(allr) if r["base"]==start["base"])
gap_total = 0
covered = 0
maxsize = 0x16000000  # cap ~384MB
while i < len(allr) and covered < maxsize:
    r = allr[i]
    if r["base"] != cur:
        gap = r["base"] - cur
        if gap > 0x10000:  # big gap -> stop contiguous image
            print(f"gap 0x{gap:x} at 0x{cur:x}, stopping stitch")
            break
        stitched.extend(b"\x00"*gap)
        covered += gap
        gap_total += gap
        cur = r["base"]
    data = read_region(r)
    # only up to actual read size
    stitched.extend(data)
    covered += len(data)
    cur = r["base"] + r["size"]
    i += 1

print(f"stitched image: 0x{len(stitched):x} bytes (gaps {gap_total/1024:.1f}KB)")

# Now parse PE header from stitched at offset (IMAGE_BASE - start.base)
hdr_off = IMAGE_BASE - start["base"]
print(f"header offset in stitched: 0x{hdr_off:x}")
dos = bytes(stitched[hdr_off:hdr_off+64])
print("DOS magic:", dos[:2])
e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
print(f"e_lfanew: 0x{e_lfanew:x}")
pe_off = hdr_off + e_lfanew
mz = stitched[pe_off:pe_off+4]
print("PE magic:", mz)
machine = struct.unpack_from("<H", stitched, pe_off+4)[0]
numsec = struct.unpack_from("<H", stitched, pe_off+4+2)[0]
szopt = struct.unpack_from("<H", stitched, pe_off+4+16)[0]
chars = struct.unpack_from("<H", stitched, pe_off+4+18)[0]
opt = bytes(stitched[pe_off+4+20:pe_off+4+20+szopt])
magic = struct.unpack_from("<H", opt, 0)[0]
ep = struct.unpack_from("<I", opt, 16)[0]
imgbase = struct.unpack_from("<Q", opt, 24)[0] if magic==0x20b else struct.unpack_from("<I", opt, 28)[0]
sizeimg = struct.unpack_from("<I", opt, 56 if magic==0x20b else 56)[0]
print(f"machine 0x{machine:x} numsec {numsec} szopt {szopt} magic 0x{magic:x} EP 0x{ep:x} ImageBase 0x{imgbase:x} SizeOfImage 0x{sizeimg:x}")

# section table
sec_off = pe_off + 4 + 20 + szopt
sections = []
for i in range(numsec):
    s = bytes(stitched[sec_off+i*40: sec_off+i*40+40])
    name = s[:8].rstrip(b"\x00").decode("latin1","replace")
    vsize = struct.unpack_from("<I", s, 8)[0]
    va = struct.unpack_from("<I", s, 12)[0]
    rawsize = struct.unpack_from("<I", s, 16)[0]
    rawptr = struct.unpack_from("<I", s, 20)[0]
    schars = struct.unpack_from("<I", s, 36)[0]
    sections.append((name, va, vsize, rawsize, rawptr, schars))
    print(f"  {name:10} VA=0x{va:08x} VS=0x{vsize:08x} RawPtr=0x{rawptr:08x} RawSize=0x{rawsize:08x} Chars=0x{schars:08x}")

# Build a new PE file: copy header (first section's raw data area), then for each section
# set RawPtr/RawSize to a file offset where we write its memory bytes (vsize aligned).
# Strategy: keep header up to first section, then lay out sections sequentially.
# Determine header size = sec_off (relative to stitched) = file header up to section table end.
header_end = sec_off + numsec*40
# round up to 0x200
file_align = 0x200
def align(v, a): return (v + a - 1) & ~(a-1)
header_size = align(header_end, file_align)  # this is relative offset within stitched from start of PE
# but we want the output to start at the DOS header (file offset hdr_off)
# build output
out = bytearray(header_size)
# copy DOS+PE header
out[:header_end] = stitched[hdr_off:hdr_off+header_end]

# patch section table: set RawPtr and RawSize
cur_off = header_size
new_secs = []
for (name, va, vsize, rawsize, rawptr, schars) in sections:
    # memory size to copy = vsize, but only up to what we have in stitched
    mem_off = hdr_off + va  # relative to stitched start
    sz = vsize
    data = bytes(stitched[mem_off: mem_off+sz])
    if len(data) < sz:
        data = data + b"\x00"*(sz-len(data))
    rawsz = align(len(data), file_align)
    # patch
    new_secs.append((name, va, vsize, rawsz, cur_off, schars, data))
    cur_off += rawsz

# rewrite section table in out
for i, (name, va, vsize, rawsz, rawptr, schars, data) in enumerate(new_secs):
    s = bytearray(40)
    s[0:8] = name.encode("latin1")[:8].ljust(8, b"\x00")
    struct.pack_into("<I", s, 8, vsize)
    struct.pack_into("<I", s, 12, va)
    struct.pack_into("<I", s, 16, rawsz)   # SizeOfRawData
    struct.pack_into("<I", s, 20, rawptr) # PointerToRawData
    struct.pack_into("<I", s, 24, 0)      # PointerToRelocations
    struct.pack_into("<I", s, 28, 0)      # PointerToLinenumbers
    struct.pack_into("<H", s, 32, 0)
    struct.pack_into("<H", s, 34, 0)
    struct.pack_into("<I", s, 36, schars)
    out[sec_off+i*40: sec_off+i*40+40] = s

# extend out to full size
out.extend(b"\x00"*(cur_off - len(out)))
# write section data
for (name, va, vsize, rawsz, rawptr, schars, data) in new_secs:
    out[rawptr: rawptr+len(data)] = data

recon = os.path.join(OUT, "AxonSkin_unpacked.exe")
with open(recon, "wb") as f:
    f.write(out)
print(f"\nreconstructed -> {recon} ({len(out)/1048576:.1f} MB)")

# quick sanity: entry point bytes
ep_off_in_img = hdr_off + ep
ep_bytes = bytes(stitched[ep_off_in_img: ep_off_in_img+32])
print(f"EP 0x{ep:x} bytes (mem): {ep_bytes.hex(' ')}")
# also from reconstructed
ep_file_off = next((rp for n,va,vs,rs,rp,ch,d in new_secs if va<=ep<va+vs), None)
if ep_file_off is not None:
    # find which section
    for (name, va, vsize, rawsz, rawptr, schars, data) in new_secs:
        if va <= ep < va+vsize:
            local = ep - va
            print(f"EP in section {name}, file bytes: {data[local:local+32].hex(' ')}")
            break
