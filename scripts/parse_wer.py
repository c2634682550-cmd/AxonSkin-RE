from minidump.minidumpfile import MinidumpFile
import sys

for path in [
    r"C:\Users\26346\AppData\Roaming\Axon\AxonSkin\crash\AxonSkin v4.1.exe.46676.dmp",
    r"C:\Users\26346\AppData\Local\CrashDumps\AxonSkin_v4.1_asInvoker.exe.42420.dmp",
]:
    print(f"\n{'='*60}\n{path}\n{'='*60}")
    try:
        mf = MinidumpFile.parse(path)
    except Exception as e:
        print(f"parse error: {e}"); continue
    # modules
    if hasattr(mf, 'modules') and mf.modules:
        print(f"\n--- modules ({len(mf.modules.modules)}) ---")
        for m in mf.modules.modules:
            # find main module
            name = m.name if hasattr(m,'name') else str(m)
            base = m.baseaddress if hasattr(m,'baseaddress') else 0
            sz = m.size if hasattr(m,'size') else 0
            if 'axon' in str(name).lower() or base < 0x8000000000000000 and sz > 0x1000000:
                print(f"  base=0x{base:x} size=0x{sz:x} {name}")
    # threads
    if hasattr(mf, 'threads') and mf.threads:
        print(f"\n--- threads ({len(mf.threads.threads)}) ---")
        for i, t in enumerate(mf.threads.threads[:10]):
            ctx = t.Context if hasattr(t,'Context') else None
            rip = 0
            if ctx:
                try: rip = getattr(ctx, 'Rip', 0)
                except: pass
            print(f"  tid={t.ThreadId} rip=0x{rip:x}")
    # memory lists
    if hasattr(mf, 'memory_segments_64') and mf.memory_segments_64:
        segs = mf.memory_segments_64.memory_segments
        print(f"\n--- memory segments ({len(segs)}) ---")
        for s in segs[:20]:
            print(f"  start=0x{s.start_virtual_address:x} size=0x{s.size:x}")
    # memory info list
    if hasattr(mf, 'memory_info') and mf.memory_info:
        infos = mf.memory_info.infos
        print(f"\n--- memory info ({len(infos)}) ---")
