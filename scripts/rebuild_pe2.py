"""
Rebuild unpacked PE from memory dump.
Auto-detect runtime image base by scanning IMAGE regions for 'MZ' header,
then stitch contiguous regions for SizeOfImage, parse section table, carve sections.
"""
import os, json, struct

OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
with open(os.path.join(OUT, "manifest.json")) as f:
    manifest = json.load(f)

# sort all regions
allr = sorted(manifest, key=lambda x: x["base"])

def read_region(r):
    with open(os.path.join(OUT, r["file"]), "rb") as f:
        return f.read()

# 1) find IMAGE regions whose data starts with 'MZ' (PE header)
print("=== scanning for MZ IMAGE regions ===")
candidates = []
for r in allr:
    if r["type"] != 0x1000000:  # MEM_IMAGE
        continue
    data = read_region(r)
    if data[:2] == b"MZ":
        candidates.append((r, data))
        if len(candidates) <= 5:
            print(f"  MZ at 0x{r['base']:x} size 0x{r['size']:x} prot 0x{r['prot']:x}")

print(f"total MZ IMAGE regions: {len(candidates)}")

# the main module is the one whose .text is huge (EXECUTE_READ, large). The main exe header region is prot 0x2 (READONLY) with small size (0x1000) and is followed by a big EXECUTE region.
# Find the header region (prot 0x2, size 0x1000) followed by big exec region
main_base = None
main_hdr_region = None
for i, (r, data) in enumerate(candidates):
    if r["prot"] == 0x2 and r["size"] <= 0x2000:
        # check e_lfanew
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 < len(data) and data[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
            # look for following exec region
            for r2 in allr:
                if r2["base"] == r["base"] + r["size"] and r2["prot"] == 0x20 and r2["size"] > 0x1000000:
                    main_base = r["base"]
                    main_hdr_region = r
                    print(f"\nMAIN MODULE: base 0x{main_base:x} (header region)")
                    print(f"  followed by exec region 0x{r2['base']:x} size 0x{r2['size']:x}")
                    break
        if main_base: break

if not main_base:
    print("FALLBACK: using first MZ IMAGE region")
    main_base = candidates[0][0]["base"]
    main_hdr_region = candidates[0][0]

# 2) parse PE header from header region to get SizeOfImage and section table
hdr_data = read_region(main_hdr_region)
if len(hdr_data) < main_hdr_region["size"]:
    hdr_data = hdr_data + b"\x00"*(main_hdr_region["size"]-len(hdr_data))
e_lfanew = struct.unpack_from("<I", hdr_data, 0x3C)[0]
pe_off = e_lfanew
machine = struct.unpack_from("<H", hdr_data, pe_off+4)[0]
numsec = struct.unpack_from("<H", hdr_data, pe_off+6)[0]
szopt = struct.unpack_from("<H", hdr_data, pe_off+20)[0]
opt = hdr_data[pe_off+24: pe_off+24+szopt]
magic = struct.unpack_from("<H", opt, 0)[0]
ep = struct.unpack_from("<I", opt, 16)[0]
is64 = (magic == 0x20b)
imgbase = struct.unpack_from("<Q", opt, 24)[0] if is64 else struct.unpack_from("<I", opt, 28)[0]
sizeimg = struct.unpack_from("<I", opt, 56)[0]
print(f"PE: machine 0x{machine:x} numsec {numsec} magic 0x{magic:x} EP 0x{ep:x} ImageBase 0x{imgbase:x} SizeOfImage 0x{sizeimg:x}")

sec_off = pe_off + 24 + szopt
sections = []
for i in range(numsec):
    s = hdr_data[sec_off+i*40: sec_off+i*40+40]
    name = s[:8].rstrip(b"\x00").decode("latin1","replace")
    vsize = struct.unpack_from("<I", s, 8)[0]
    va = struct.unpack_from("<I", s, 12)[0]
    rawsize = struct.unpack_from("<I", s, 16)[0]
    rawptr = struct.unpack_from("<I", s, 20)[0]
    schars = struct.unpack_from("<I", s, 36)[0]
    sections.append((name, va, vsize, rawsize, rawptr, schars))
    print(f"  {name:10} VA=0x{va:08x} VS=0x{vsize:08x}")

# 3) build region lookup: map base address -> region data
region_map = {}
for r in manifest:
    region_map[r["base"]] = r

# 4) stitch the full image of sizeimg bytes starting at main_base
# read memory in 4KB pages by finding the region containing each page
def read_mem(addr, length):
    """Read length bytes from addr using region_map. Returns bytes, zero-filled for unmapped."""
    out = bytearray(length)
    end = addr + length
    cur = addr
    # find regions overlapping [addr, end)
    for r in manifest:
        rb = r["base"]
        rs = r["size"]
        re_ = rb + rs
        if re_ <= addr or rb >= end:
            continue
        # overlap
        start = max(addr, rb)
        stop = min(end, re_)
        if stop <= start:
            continue
        data = read_region(r)
        # data may be shorter than r.size (nread)
        doff = start - rb
        dlen = min(stop - start, len(data) - doff)
        if dlen > 0:
            out[start-addr: start-addr+dlen] = data[doff: doff+dlen]
    return bytes(out)

print(f"\nreading full image 0x{sizeimg:x} bytes from 0x{main_base:x} ...")
image = read_mem(main_base, sizeimg)
print(f"image bytes read: 0x{len(image):x}")

# verify header
print(f"image[:2] = {image[:2]}")

# 5) rebuild PE: header + sections laid out per file alignment
file_align = 0x200
def align(v, a): return (v + a - 1) & ~(a-1)

# header region in image
header_size_bytes = sec_off + numsec*40  # end of section table
header_size = align(header_size_bytes, file_align)

out = bytearray(header_size)
out[:header_size_bytes] = image[:header_size_bytes]

# lay out sections
cur_off = header_size
new_secs = []
for (name, va, vsize, rawsize, rawptr, schars) in sections:
    sz = vsize
    sec_data = image[va: va+sz]
    if len(sec_data) < sz:
        sec_data = sec_data + b"\x00"*(sz-len(sec_data))
    rawsz = align(len(sec_data), file_align)
    new_secs.append((name, va, vsize, rawsz, cur_off, schars, sec_data))
    cur_off += rawsz

# rewrite section table rawptr/rawsize
for i, (name, va, vsize, rawsz, rawptr, schars, data) in enumerate(new_secs):
    s = bytearray(40)
    s[0:8] = name.encode("latin1")[:8].ljust(8, b"\x00")
    struct.pack_into("<I", s, 8, vsize)
    struct.pack_into("<I", s, 12, va)
    struct.pack_into("<I", s, 16, rawsz)
    struct.pack_into("<I", s, 20, rawptr)
    struct.pack_into("<I", s, 36, schars)
    out[sec_off+i*40: sec_off+i*40+40] = s

# extend out
out.extend(b"\x00"*(cur_off - len(out)))
for (name, va, vsize, rawsz, rawptr, schars, data) in new_secs:
    out[rawptr: rawptr+len(data)] = data

recon = os.path.join(OUT, "AxonSkin_unpacked.exe")
with open(recon, "wb") as f:
    f.write(out)
print(f"\nreconstructed -> {recon} ({len(out)/1048576:.1f} MB)")

# verify EP bytes
for (name, va, vsize, rawsz, rawptr, schars, data) in new_secs:
    if va <= ep < va+vsize:
        local = ep - va
        print(f"EP 0x{ep:x} in section {name}, file bytes: {data[local:local+32].hex(' ')}")
        break
