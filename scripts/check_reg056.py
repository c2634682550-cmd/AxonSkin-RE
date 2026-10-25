"""Check if reg_056 (0x7ff7b3a5c000, 30MB EXECUTE) contains real decrypted Qt code.
Also check reg_075 (15.7MB EXECUTE) and the .text region of the main module."""
import os, struct
REG = r"C:\Users\26346\AppData\Local\Temp\axon_regions"

def check(name, label):
    path = os.path.join(REG, name)
    if not os.path.exists(path):
        print(f"{label}: MISSING {name}"); return
    data = open(path,"rb").read()
    nz = sum(1 for b in data if b!=0)
    # x64 prologues
    p1 = data.count(bytes([0x48,0x89,0x5c,0x24]))  # mov [rsp+x],rbx
    p2 = data.count(bytes([0x48,0x83,0xec]))        # sub rsp,x
    p3 = data.count(bytes([0x55,0x48,0x89]))        # push rbp; mov
    calls = data.count(b"\xe8")
    retn = data.count(b"\xc3")
    int3 = data.count(b"\xcc"*4)
    # Qt strings
    qt = 0
    for s in [b"QObject", b"QWidget", b"QApplication", b"QString", b"QTimer", b"QPushButton", b"QMainWindow", b"Qt6", b"QEvent"]:
        qt += data.count(s)
    # Chinese strings (UTF-8常见字节)
    # look for UTF-16LE Chinese
    cn16 = 0
    for i in range(0, len(data)-1, 2):
        if data[i] >= 0x00 and data[i+1] == 0x4e:  # CJK range 0x4Exx-0x9Fxx
            cn16 += 1
            break
    print(f"{label}: {len(data)/1048576:.1f}MB nz={nz/len(data)*100:.1f}% prologue={p1} subrsp={p2} pushrbp={p3} calls={calls} retn={retn} int3pad={int3} qtstrings={qt}")
    print(f"  head: {data[:32].hex(' ')}")
    # find first valid code sequence
    for i in range(len(data)-4):
        if data[i]==0x48 and data[i+1]==0x89 and data[i+2]==0x5c and data[i+3]==0x24:
            print(f"  first prologue at off 0x{i:x}: {data[i:i+16].hex(' ')}")
            break
    # search for interesting strings
    import re
    ss = re.findall(b"[\x20-\x7e]{8,}", data[:0x100000])
    interesting = [s.decode() for s in ss if any(k in s.lower() for k in [b'axon',b'skin',b'qt',b'config',b'http',b'json',b'login',b'trial',b'.dll',b'.exe',b'window'])]
    print(f"  interesting strings (first 256K): {interesting[:15]}")

# reg_056: 30MB EXECUTE right after main module header
check("reg_056_7ff7b3a5c000.bin", "reg_056 (30MB EXECUTE)")
# reg_075: 15.7MB EXECUTE
check("reg_075_7ff7c3a5d000.bin", "reg_075 (15.7MB EXECUTE)")
# reg_060: 112MB WRITECOPY (the .jgaz section data)
check("reg_060_7ff7bc94c000.bin", "reg_060 (112MB WRITECOPY)")
# reg_048: 3.2MB READONLY
check("reg_048_19775000000.bin", "reg_048 (3.2MB RO)")
# reg_052: 19.2MB
check("reg_052_19775dd0000.bin", "reg_052 (19.2MB)")
