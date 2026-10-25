import json, os
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack"
with open(os.path.join(OUT,"manifest.json")) as f:
    m = json.load(f)

MEM_IMAGE = 0x1000000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000

print("=== region count by type ===")
from collections import Counter
tc = Counter(r["type"] for r in m)
for t,c in tc.items():
    nm = {MEM_IMAGE:"IMAGE",MEM_PRIVATE:"PRIVATE",MEM_MAPPED:"MAPPED"}.get(t, hex(t))
    print(f"  type 0x{t:x} ({nm}): {c}")

print("\n=== IMAGE-type regions (mapped modules) ===")
imgs = [r for r in m if r["type"]==MEM_IMAGE]
imgs.sort(key=lambda x:x["base"])
for r in imgs:
    print(f"  base 0x{r['base']:016x} size 0x{r['size']:08x} prot 0x{r['prot']:x} -> {r['file']}")

print("\n=== largest PRIVATE regions (unpacked code/data) ===")
priv = [r for r in m if r["type"]==MEM_PRIVATE]
priv.sort(key=lambda x:-x["size"])
for r in priv[:25]:
    print(f"  base 0x{r['base']:016x} size 0x{r['size']:08x} ({r['size']/1048576:.1f}MB) prot 0x{r['prot']:x} -> {r['file']}")

print("\n=== regions near 0x140000000 (within +/-16MB) ===")
for r in sorted(m, key=lambda x:x["base"]):
    if abs(r["base"] - 0x140000000) < 0x1000000:
        print(f"  base 0x{r['base']:016x} size 0x{r['size']:08x} prot 0x{r['prot']:x} type 0x{r['type']:x} -> {r['file']}")
