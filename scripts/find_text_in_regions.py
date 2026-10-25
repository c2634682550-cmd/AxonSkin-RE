"""Search axon_regions index for .text section coverage and find any decrypted code regions.
Also check if there's a region containing the crash address RVA 0x3bdf59."""
import json
REG = r"C:\Users\26346\AppData\Local\Temp\axon_regions"
with open(REG + r"\index.json") as f:
    idx = json.load(f)
regions = idx["regions"]
MAIN_BASE = 0x7ff7afb90000  # main module base

# .text: RVA 0x1000, size 0x26092cd
text_start = MAIN_BASE + 0x1000
text_end = MAIN_BASE + 0x1000 + 0x26092cd
# .s0w: RVA 0x3ecc000, size 0x1df7000
s0w_start = MAIN_BASE + 0x3ecc000
s0w_end = MAIN_BASE + 0x3ecc000 + 0x1df7000
# .jgaz: RVA 0xcdb4000, size 0x80d0000
jgaz_start = MAIN_BASE + 0xcdb4000

print(f"Main module base: 0x{MAIN_BASE:x}")
print(f".text range: 0x{text_start:x} - 0x{text_end:x} (38MB)")
print(f".s0w range:  0x{s0w_start:x} - 0x{s0w_end:x} (30MB)")
print()

# Find ALL regions that overlap with .text
print("=== Regions overlapping .text ===")
for r in regions:
    a = r["addr"]; s = r["size"]; e = a + s
    if a < text_end and e > text_start:
        nz = r.get("nonzero",0)
        p = r["protect"]
        print(f"  0x{a:x} size=0x{s:x} prot=0x{p:x} nz={nz:.3f} {r['file']}")

# Also find regions near the crash address (RVA 0x3bdf59)
crash_va = MAIN_BASE + 0x3bdf59
print(f"\n=== Region containing crash addr 0x{crash_va:x} (RVA 0x3bdf59) ===")
for r in regions:
    a = r["addr"]; s = r["size"]; e = a + s
    if a <= crash_va < e:
        print(f"  0x{a:x} size=0x{s:x} prot=0x{r['protect']:x} nz={r.get('nonzero',0):.3f} {r['file']}")
        # read and check if it's real code
        data = open(REG + "\\" + r["file"], "rb").read()
        off = crash_va - a
        print(f"  crash offset in region: 0x{off:x}")
        print(f"  bytes at crash: {data[off:off+32].hex(' ')}")
        # check nearby for prologues
        nearby = data[max(0,off-0x100):off+0x100]
        prologues = nearby.count(bytes([0x48,0x89,0x5c,0x24]))
        print(f"  prologues nearby: {prologues}")

# Check which big EXECUTE regions have real code (non-garbled strings)
print("\n=== Big EXECUTE regions with string check ===")
import re
for r in regions:
    if r["protect"] == 0x20 and r["size"] > 0x100000:
        data = open(REG + "\\" + r["file"], "rb").read(0x100000)
        ss = re.findall(b"[\x20-\x7e]{8,}", data)
        real = [s.decode() for s in ss if any(c.isalpha() for c in s.decode()) and not all(c in "ABCDEFGH" for c in s.decode())]
        # check for known DLL/API names
        known = [s for s in real if any(k in s for k in ["ntdll","kernel32","user32","Qt","QObject","QWidget","MessageBox","CreateFile","VirtualAlloc","LoadLibrary","GetProcAddress"])]
        print(f"  0x{r['addr']:x} {r['size']/1048576:.1f}MB nz={r.get('nonzero',0):.2f} known_strings={known[:5]}")
