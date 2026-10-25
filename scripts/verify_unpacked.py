import os, struct, pefile

RECON = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack\AxonSkin_unpacked.exe"
pe = pefile.PE(RECON, fast_load=True)

print("=== rebuilt PE sections ===")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1','replace')
    data = s.get_data()
    # entropy + non-zero
    nz = sum(1 for b in data if b != 0)
    # first 32 bytes
    head = data[:32].hex(' ')
    asc = ''.join(chr(b) if 32<=b<=126 else '.' for b in data[:32])
    print(f"{name:10} VS=0x{s.Misc_VirtualSize:08x} RS=0x{s.SizeOfRawData:08x} nonZero={nz}/{len(data)} ({100*nz/max(1,len(data)):.1f}%)")
    print(f"  head: {head}")
    print(f"  asc:  |{asc}|")

# check .text specifically - is it real code?
text = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text = s.get_data()
        break

if text:
    print(f"\n=== .text analysis ===")
    print(f"size: {len(text)} bytes ({len(text)/1048576:.1f} MB)")
    # check for typical x64 function prologues
    prologues = {
        b'\x48\x89\x5c\x24': "mov [rsp+x],rbx",
        b'\x48\x89\x6c\x24': "mov [rsp+x],rbp",
        b'\x48\x89\x74\x24': "mov [rsp+x],rsi",
        b'\x48\x89\x7c\x24': "mov [rsp+x],rdi",
        b'\x48\x8b\xc4': "mov rax,rsp",
        b'\x40\x53': "push rbx",
        b'\x40\x55': "push rbp",
        b'\x40\x56': "push rsi",
        b'\x40\x57': "push rdi",
        b'\x48\x83\xec': "sub rsp,x",
        b'\x55': "push rbp (legacy)",
        b'\x48\x89\x23': "store...",
    }
    hits = {}
    for pat, desc in prologues.items():
        cnt = text.count(pat)
        if cnt > 0:
            hits[desc] = cnt
    print("x64 prologue hits:")
    for k,v in sorted(hits.items(), key=lambda x:-x[1]):
        print(f"  {k}: {v}")
    # call/jmp density
    import collections
    cc = text.count(b'\xe8')  # near call rel32
    jc = text.count(b'\xe9')  # near jmp rel32
    retn = text.count(b'\xc3')
    print(f"call(e8)={cc} jmp(e9)={jc} retn(c3)={retn}")
    # first 1KB
    print(f"\n.text first 256 bytes:")
    for i in range(0, 256, 16):
        chunk = text[i:i+16]
        print(f"  {i:04x}: {chunk.hex(' ')}")

# also check if IAT is populated
print(f"\n=== IAT check ===")
pe.parse_data_directories()
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:
        print(f"DLL: {entry.dll.decode()}")
        for imp in entry.imports[:3]:
            print(f"  {imp.name} @ 0x{imp.address:x}")
