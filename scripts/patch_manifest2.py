"""Replace manifest with a valid asInvoker manifest, padding with newlines to original size."""
SRC = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
DST = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack\AxonSkin_v4.1_asInvoker.exe"
import shutil, pefile
shutil.copy2(SRC, DST)

NEW = (
    "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\r\n"
    "<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>\r\n"
    "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n"
    "    <security>\r\n"
    "      <requestedPrivileges>\r\n"
    "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />\r\n"
    "      </requestedPrivileges>\r\n"
    "    </security>\r\n"
    "  </trustInfo>\r\n"
    "</assembly>\r\n"
).encode("utf-8")

pe = pefile.PE(DST)
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.id == 24:
        for sub in entry.directory.entries:
            for lang in sub.directory.entries:
                data_rva = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                off = pe.get_offset_from_rva(data_rva)
                assert len(NEW) <= size, f"new {len(NEW)} > old {size}"
                padded = NEW + b"\r\n" * (size - len(NEW))
                with open(DST, "r+b") as f:
                    f.seek(off); f.write(padded)
                print(f"manifest rewritten at 0x{off:x} size={size} (new xml {len(NEW)})")
print("done")
