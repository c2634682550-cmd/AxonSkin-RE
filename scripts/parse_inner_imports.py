import pefile, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axon_inner.bin")
iat_rva = 0x4bf8c; iat_size = 0xa0
data = pe.get_data(iat_rva, iat_size)
off = 0
while off + 20 <= len(data):
    oft, tds, fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
    off += 20
    if oft == 0 and name_rva == 0: break
    try:
        name = pe.get_data(name_rva, 64).split(b"\x00")[0].decode("ascii","replace")
    except: name = "?"
    print(f"{name}: OFT=0x{oft:x} FT=0x{ft:x}")
    thunk = oft if oft else ft
    i = 0
    while True:
        try:
            val = struct.unpack_from("<Q", pe.get_data(thunk + i*8, 8))[0]
        except: break
        if val == 0: break
        if val & (1<<63):
            print(f"  #{val & 0xFFFF}")
        else:
            try:
                fn = pe.get_data(val + 2, 64).split(b"\x00")[0].decode("ascii","replace")
                print(f"  {fn}")
            except:
                print(f"  ?0x{val:x}")
        i += 1
        if i > 50: break
