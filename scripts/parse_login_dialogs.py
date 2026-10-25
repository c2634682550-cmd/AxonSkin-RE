"""Parse dialog templates from axonlogin.dll .rsrc section (resource ID 0x66 and 0x6A)."""
import pefile, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin.dll")
base = pe.OPTIONAL_HEADER.ImageBase

RT_DIALOG = 5
dialogs = {}
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.id == RT_DIALOG:
        for sub in entry.directory.entries:
            for lang in sub.directory.entries:
                data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                dialogs[sub.id] = data

print(f"Dialog resources found: {len(dialogs)} (IDs: {sorted(dialogs.keys())})")

def read_sz_w(data, off):
    """Read null-terminated UTF-16LE string from data at off."""
    if off + 2 > len(data):
        return "", off
    if struct.unpack_from("<H", data, off)[0] == 0:
        return "", off + 2
    if struct.unpack_from("<H", data, off)[0] == 0xFFFF:
        rid = struct.unpack_from("<H", data, off + 2)[0]
        return f"#{rid}", off + 4
    s = []
    while off < len(data) - 1:
        c = struct.unpack_from("<H", data, off)[0]
        off += 2
        if c == 0:
            break
        s.append(chr(c))
    return "".join(s), off

for did, data in sorted(dialogs.items()):
    print(f"\n{'='*60}")
    print(f"Dialog ID 0x{did:x} ({did}) - {len(data)} bytes")
    print(f"{'='*60}")
    off = 0
    ver = struct.unpack_from("<H", data, 0)[0] if len(data) >= 2 else 0
    if ver == 1 and len(data) >= 4 and struct.unpack_from("<H", data, 2)[0] == 0xFFFF:
        # DLGTEMPLATEEX
        ver, sig = struct.unpack_from("<HH", data, 0)
        helpid, exstyle, style, n_items, x, y, cx, cy = struct.unpack_from("<IHHHHHHH", data, 4) if len(data) >= 22 else (0,0,0,0,0,0,0,0)
        off = 26
        is_ex = True
        print(f"  [EX] style=0x{style:08x} exstyle=0x{exstyle:08x} items={n_items}")
    else:
        # DLGTEMPLATE
        if len(data) >= 18:
            style = struct.unpack_from("<I", data, 0)[0]
            exstyle = struct.unpack_from("<I", data, 4)[0]
            n_items = struct.unpack_from("<H", data, 8)[0]
            x, y, cx, cy = struct.unpack_from("<hhhh", data, 10)
            off = 18
            is_ex = False
            print(f"  style=0x{style:08x} exstyle=0x{exstyle:08x} items={n_items}")
        else:
            print("  (too small)")
            continue

    print(f"  pos=({x},{y}) size=({cx},{cy})")

    menu, off = read_sz_w(data, off)
    cls, off = read_sz_w(data, off)
    title, off = read_sz_w(data, off)
    print(f"  title='{title}' menu='{menu}' class='{cls}'")

    if style & 0x40:  # DS_SETFONT
        if is_ex:
            if off + 6 <= len(data):
                pt, weight, italic, charset = struct.unpack_from("<HHBB", data, off)
                off += 6
        else:
            if off + 2 <= len(data):
                pt = struct.unpack_from("<H", data, off)[0]
                off += 2
        fontname, off = read_sz_w(data, off)
        print(f"  font='{fontname}' pt={pt}")

    # align to DWORD
    if off % 4:
        off += 4 - (off % 4)

    for i in range(n_items):
        if off + 12 > len(data):
            break
        if is_ex:
            if off + 24 > len(data):
                break
            helpid2, exstyle2, style2 = struct.unpack_from("<IHH", data, off)
            off += 8
        else:
            style2, exstyle2 = struct.unpack_from("<II", data, off)
            off += 8

        x2, y2, cx2, cy2, ctrl_id = struct.unpack_from("<hhhhH", data, off)
        off += 10
        cls_str, off = read_sz_w(data, off)
        text, off = read_sz_w(data, off)
        extra_len = struct.unpack_from("<H", data, off)[0] if off + 2 <= len(data) else 0
        off += 2 + extra_len
        if off % 4:
            off += 4 - (off % 4)
        print(f"  ctrl id={ctrl_id} (0x{ctrl_id:x}) cls='{cls_str}' text='{text}' pos=({x2},{y2}) size=({cx2},{cy2}) style=0x{style2:x}")
