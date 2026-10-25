"""Patch the RT_MANIFEST from requireAdministrator -> asInvoker and save a copy for unpacking."""
import pefile, shutil, os

SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
DST = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack\AxonSkin_v4.1_asInvoker.exe"
shutil.copy2(SRC, DST)

pe = pefile.PE(DST)
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.id == 24:  # RT_MANIFEST
        for sub in entry.directory.entries:
            for lang in sub.directory.entries:
                data_rva = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                # rva -> file offset
                # overlay_offset = pe.get_offset_from_rva(data_rva)
                off = pe.get_offset_from_rva(data_rva)
                with open(DST, "r+b") as f:
                    f.seek(off)
                    data = f.read(size)
                    print("before:", data)
                    new = data.replace(b"requireAdministrator", b"asInvoker          ")
                    # the replacement is same length, safe
                    print("after :", new)
                    f.seek(off)
                    f.write(new)
                print(f"patched at file offset 0x{off:x}, size {size}")
print("done ->", DST)
