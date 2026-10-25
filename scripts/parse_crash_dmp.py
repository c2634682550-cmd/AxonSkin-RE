"""Parse crash minidump to get module list and exception info.
Uses manual parsing to avoid minidump library bugs."""
import sys, os, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re"
crash_dir = os.path.join(os.environ.get('APPDATA', ''), "Axon", "AxonSkin", "crash")

dmp_file = os.path.join(crash_dir, "crash-20261025-205936.dmp")
if not os.path.exists(dmp_file):
    dmp_file = os.path.join(crash_dir, "AxonSkin v4.1.exe.46676.dmp")

print(f"Analyzing: {os.path.basename(dmp_file)}")
print(f"Size: {os.path.getsize(dmp_file)} bytes")

with open(dmp_file, 'rb') as f:
    data = f.read()

# Parse minidump header
# MINIDUMP_HEADER: Signature(4) + Version(4) + NumberOfStreams(4) + StreamDirectoryRVA(4) + CheckSum(4) + TimeDateStamp(4) + Flags(8)
sig = struct.unpack_from('<I', data, 0)[0]
print(f"Signature: 0x{sig:08x} ({'MDMP' if sig == 0x504D444D else 'UNKNOWN'})")

num_streams = struct.unpack_from('<I', data, 8)[0]
stream_rva = struct.unpack_from('<I', data, 12)[0]
print(f"Streams: {num_streams}, Directory RVA: 0x{stream_rva:x}")

# Parse stream directory
# Each entry: StreamType(4) + DataSize(4) + RVA(4)
modules = []
for i in range(num_streams):
    offset = stream_rva + i * 12
    stream_type = struct.unpack_from('<I', data, offset)[0]
    data_size = struct.unpack_from('<I', data, offset + 4)[0]
    rva = struct.unpack_from('<I', data, offset + 8)[0]
    
    # Stream types
    # 4 = ModuleListStream
    # 7 = SystemInfoStream
    # 6 = ExceptionStream
    # 9 = MemoryListStream
    # 15 = ThreadInfoListStream
    
    if stream_type == 4:  # ModuleListStream
        # MINIDUMP_MODULE_LIST: NumberOfModules(4) + Modules[]
        num_modules = struct.unpack_from('<I', data, rva)[0]
        print(f"\n=== Module List ({num_modules} modules) ===")
        
        mod_offset = rva + 4
        for j in range(min(num_modules, 200)):
            # MINIDUMP_MODULE: BaseOfImage(8) + SizeOfImage(4) + CheckSum(4) + TimeDateStamp(4) + ModuleNameRVA(4) + VersionInfo(13*4) + CvRecord(8) + MiscRecord(8) + Reserved0(8) + Reserved1(8)
            base = struct.unpack_from('<Q', data, mod_offset)[0]
            size = struct.unpack_from('<I', data, mod_offset + 8)[0]
            checksum = struct.unpack_from('<I', data, mod_offset + 12)[0]
            timestamp = struct.unpack_from('<I', data, mod_offset + 16)[0]
            name_rva = struct.unpack_from('<I', data, mod_offset + 20)[0]
            
            # Read module name (MINIDUMP_STRING: Length(4) + WCHAR[])
            if name_rva > 0 and name_rva < len(data):
                name_len = struct.unpack_from('<I', data, name_rva)[0]
                name_bytes = data[name_rva + 4 : name_rva + 4 + min(name_len, 500)]
                try:
                    name = name_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
                except:
                    name = f"<decode error at 0x{name_rva:x}>"
            else:
                name = "<no name>"
            
            modules.append((base, size, name))
            
            # Only print interesting modules
            short_name = os.path.basename(name) if name and not name.startswith('<') else name
            if any(k in name.lower() for k in ['axon', 'qt', 'd3d', 'dxgi', 'dwrite', 'interception', 'msvcp', 'vcruntime', 'concrt', 'api-ms', 'kernel32', 'user32', 'gdi32', 'winhttp', 'ws2_32', 'ole32', 'shell32', 'comctl32', 'crypt', 'ncrypt', 'bcrypt', 'dwmapi', 'uxtheme', 'gdiplus', 'winmm', 'imm32', 'setupapi', 'wtsapi32', 'dbghelp', 'version', 'shlwapi', 'shcore', 'advapi32', 'ntdll', 'win32u', 'kernelbase']):
                print(f"  0x{base:012x} size=0x{size:08x} {short_name}")
            
            mod_offset += 108  # sizeof(MINIDUMP_MODULE) = 108

    elif stream_type == 6:  # ExceptionStream
        # MINIDUMP_EXCEPTION_STREAM: ThreadId(4) + Alignment(4) + EXCEPTION_RECORD(56) + ThreadContextRVA(4) + Size(4)
        thread_id = struct.unpack_from('<I', data, rva)[0]
        exc_code = struct.unpack_from('<I', data, rva + 8)[0]
        exc_addr = struct.unpack_from('<Q', data, rva + 16)[0]
        num_params = struct.unpack_from('<I', data, rva + 24)[0]
        print(f"\n=== Exception ===")
        print(f"  Thread ID: {thread_id}")
        print(f"  Code: 0x{exc_code:08x}")
        print(f"  Address: 0x{exc_addr:016x}")
        print(f"  Num params: {num_params}")
        
        # Find which module the exception is in
        for base, size, name in modules:
            if base <= exc_addr < base + size:
                rva_in_mod = exc_addr - base
                print(f"  Module: {os.path.basename(name)} + 0x{rva_in_mod:x}")

# Print full module count
print(f"\nTotal modules loaded: {len(modules)}")

# Print ALL modules
print(f"\n=== All Modules ===")
for base, size, name in sorted(modules, key=lambda x: x[0]):
    short = name.split('\\')[-1] if '\\' in name else name.split('/')[-1]
    print(f"  0x{base:012x} sz=0x{size:08x} {short}")
