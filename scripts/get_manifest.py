import pefile, sys, struct

TARGET = r"C:\Users\26346\Downloads\AxonSkin v4.1.exe"
pe = pefile.PE(TARGET)

# find RT_MANIFEST (type 24)
manifest = None
manifest_entry = None
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.id == 24:  # RT_MANIFEST
        for sub in entry.directory.entries:
            for lang in sub.directory.entries:
                data_rva = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                manifest = pe.get_data(data_rva, size)
                manifest_entry = (entry, sub, lang)
                print(f"RT_MANIFEST found: rva=0x{data_rva:x} size={size}")
                print("--- manifest content ---")
                try:
                    print(manifest.decode('utf-8', 'replace'))
                except:
                    print(manifest)
                print("--- end ---")
                break

if manifest is None:
    print("No manifest found")
    # dump all resource types
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        nm = pefile.RESOURCE_TYPE.get(entry.id, entry.id) if entry.id else entry.name
        print(f"type={nm}")
