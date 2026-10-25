"""Extract and parse all dialog resources from axon_inner.bin .rsrc section.
Dialog templates reveal all UI controls, button labels, text."""
import pefile, struct

pe = pefile.PE(r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axon_inner.bin")

# RT_DIALOG = 5
dialogs = []
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.id == 5:  # RT_DIALOG
        for sub in entry.directory.entries:
            for lang in sub.directory.entries:
                data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                dialog_id = sub.id
                dialogs.append((dialog_id, data))

print(f"Dialog resources: {len(dialogs)}")

def parse_dialog(data, did):
    # DLGTEMPLATEEX or DLGTEMPLATE
    # Check if it's DLGTEMPLATEEX (0x0001 0xFFFF)
    off = 0
    ver = struct.unpack_from("<H", data, 0)[0]
    if ver == 1 and struct.unpack_from("<H", data, 2)[0] == 0xFFFF:
        # DLGTEMPLATEEX
        ver, sig = struct.unpack_from("<HH", data, 0)
        helpid, exstyle, style, n_items, x, y, cx, cy = struct.unpack_from("<IHHHHHHH", data, 4)
        off = 26
        print(f"\n=== Dialog {did} (EX) style=0x{style:08x} items={n_items} pos=({x},{y}) size=({cx},{cy}) ===")
    else:
        # DLGTEMPLATE
        style = struct.unpack_from("<I", data, 0)[0]
        exstyle = struct.unpack_from("<I", data, 4)[0] if len(data)>8 else 0
        n_items = struct.unpack_from("<H", data, 8)[0]
        x, y, cx, cy = struct.unpack_from("<hhhh", data, 10)
        off = 18
        print(f"\n=== Dialog {did} style=0x{style:08x} items={n_items} pos=({x},{y}) size=({cx},{cy}) ===")

    # Skip menu, class, title (variable-length UTF-16 strings)
    def read_sz(data, off):
        if off+2 > len(data): return "", off
        if struct.unpack_from("<H", data, off)[0] == 0:
            return "", off+2
        # check if it's a resource id (0xFFFF prefix)
        if struct.unpack_from("<H", data, off)[0] == 0xFFFF:
            rid = struct.unpack_from("<H", data, off+2)[0]
            return f"#{rid}", off+4
        s = []
        while off < len(data)-1:
            c = struct.unpack_from("<H", data, off)[0]
            off += 2
            if c == 0: break
            s.append(chr(c))
        return "".join(s), off

    menu, off = read_sz(data, off)
    cls, off = read_sz(data, off)
    title, off = read_sz(data, off)
    print(f"  title='{title}' menu={menu} class={cls}")

    # If DS_SETFONT, read font info
    if style & 0x40:  # DS_SETFONT
        if ver == 1:
            pt, weight, italic, charset = struct.unpack_from("<HHBB", data, off)
            off += 6
        else:
            pt = struct.unpack_from("<H", data, off)[0]
            off += 2
        fontname, off = read_sz(data, off)
        print(f"  font='{fontname}' pt={pt}")

    # Read control items
    # align to DWORD
    if off % 4: off += 4 - (off % 4)
    for i in range(n_items):
        if ver == 1:
            if off + 24 > len(data): break
            helpid2, exstyle2, style2 = struct.unpack_from("<IHH", data, off)
            off += 8
        else:
            if off + 12 > len(data): break
            style2, exstyle2 = struct.unpack_from("<II", data, off)
            off += 8
        x2, y2, cx2, cy2, ctrl_id = struct.unpack_from("<hhhhH", data, off)
        off += 10
        cls_str, off = read_sz(data, off)
        text, off = read_sz(data, off)
        # extra data
        extra_len = struct.unpack_from("<H", data, off)[0] if off+2 <= len(data) else 0
        off += 2 + extra_len
        # align
        if off % 4: off += 4 - (off % 4)
        print(f"  ctrl id={ctrl_id} cls='{cls_str}' text='{text}' pos=({x2},{y2}) size=({cx2},{cy2}) style=0x{style2:x}")

for did, data in sorted(dialogs):
    try:
        parse_dialog(data, did)
    except Exception as e:
        print(f"  Dialog {did} parse error: {e}")
