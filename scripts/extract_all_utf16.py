"""Extract ALL meaningful UTF-16LE strings from axonlogin.dll .rdata"""
import pefile, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll")
base = pe.OPTIONAL_HEADER.ImageBase

# Extract from ALL sections, not just .rdata
all_strings = []
for sec in pe.sections:
    sec_name = sec.Name.rstrip(b'\x00').decode()
    data = sec.get_data()
    sec_va = base + sec.VirtualAddress
    i = 0
    while i < len(data) - 3:
        if data[i] != 0 and data[i+1] == 0:
            end = i
            while end < len(data) - 1:
                if data[end] == 0 and data[end+1] == 0:
                    break
                end += 2
            if end - i >= 4:
                try:
                    s = data[i:end].decode('utf-16-le', errors='strict')
                    if len(s) >= 2 and any(c.isprintable() for c in s):
                        rva = sec.VirtualAddress + i
                        all_strings.append((sec_name, base + rva, s))
                except:
                    pass
            i = end + 2
        else:
            i += 2

# Filter to meaningful strings only
meaningful = []
for sec, addr, s in all_strings:
    # Skip pure garbage (non-printable heavy)
    printable = sum(1 for c in s if c.isprintable() or c in '\r\n\t')
    if printable >= len(s) * 0.7 and len(s.strip()) >= 2:
        meaningful.append((sec, addr, s.strip()))

print(f"Total meaningful UTF-16LE strings: {len(meaningful)}")
for sec, addr, s in meaningful:
    # Truncate very long strings
    display = s if len(s) <= 120 else s[:117] + "..."
    print(f"  [{sec}] 0x{addr:x}: {display}")
