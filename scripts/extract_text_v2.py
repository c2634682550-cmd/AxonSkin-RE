"""Extract the main module's PE headers and .text section from the minidump.
Main module base: 0x7ff78e700000 (336.8MB)"""
import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

md_file = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6\full.dmp"
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6"

with open(md_file, "rb") as f:
    # Parse header
    hdr = f.read(32)
    num_streams = struct.unpack_from('<I', hdr, 8)[0]
    stream_dir_rva = struct.unpack_from('<I', hdr, 12)[0]
    
    f.seek(stream_dir_rva)
    streams = []
    for i in range(num_streams):
        st, ds, rva = struct.unpack_from('<III', f.read(12))
        streams.append((st, ds, rva))
    
    # Find Memory64ListStream (type 9)
    for st, ds, rva in streams:
        if st == 9:
            f.seek(rva)
            num_ranges = struct.unpack_from('<Q', f.read(8))[0]
            base_rva = struct.unpack_from('<Q', f.read(8))[0]
            
            # Build address->file_offset map
            cur_offset = base_rva
            ranges = []
            for j in range(num_ranges):
                start = struct.unpack_from('<Q', f.read(8))[0]
                size = struct.unpack_from('<Q', f.read(8))[0]
                ranges.append((start, size, cur_offset))
                cur_offset += size
            
            # Find the range containing main module base 0x7ff78e700000
            main_base = 0x7ff78e700000
            for start, size, foff in ranges:
                if start <= main_base < start + size:
                    main_foff = foff + (main_base - start)
                    print(f"Main module at file offset 0x{main_foff:x} (range 0x{start:x}+0x{size:x})")
                    
                    # Read PE headers
                    f.seek(main_foff)
                    pe_hdr = f.read(0x800)
                    if pe_hdr[:2] == b'MZ':
                        print("MZ header found!")
                        e_lfanew = struct.unpack_from('<I', pe_hdr, 0x3C)[0]
                        print(f"e_lfanew = 0x{e_lfanew:x}")
                        if pe_hdr[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                            num_sections = struct.unpack_from('<H', pe_hdr, e_lfanew+6)[0]
                            opt_size = struct.unpack_from('<H', pe_hdr, e_lfanew+20)[0]
                            # Image base from optional header
                            magic = struct.unpack_from('<H', pe_hdr, e_lfanew+24)[0]
                            if magic == 0x20b:  # PE32+
                                img_base = struct.unpack_from('<Q', pe_hdr, e_lfanew+24+24)[0]
                                entry = struct.unpack_from('<I', pe_hdr, e_lfanew+24+16)[0]
                                print(f"PE32+ ImageBase=0x{img_base:x} EntryPoint=0x{entry:x}")
                            print(f"Sections: {num_sections}, OptSize: 0x{opt_size:x}")
                            sec_table = e_lfanew + 24 + opt_size
                            
                            text_va = None
                            text_vsize = None
                            for i in range(num_sections):
                                s = pe_hdr[sec_table + i*40 : sec_table + (i+1)*40]
                                sname = s[:8].rstrip(b'\x00').decode('ascii','replace')
                                vsize = struct.unpack_from('<I', s, 8)[0]
                                va = struct.unpack_from('<I', s, 12)[0]
                                rawsize = struct.unpack_from('<I', s, 16)[0]
                                chars = struct.unpack_from('<I', s, 36)[0]
                                print(f"  {sname:10s} VA=0x{va:08x} VSize=0x{vsize:08x} ({vsize/1048576:7.1f}MB) RawSize=0x{rawsize:08x} Chars=0x{chars:08x}")
                                
                                if sname == '.text':
                                    text_va = va
                                    text_vsize = vsize
                            
                            # Extract .text
                            if text_va:
                                print(f"\n=== Extracting .text at VA 0x{text_va:x}, VSize 0x{text_vsize:x} ===")
                                text_file_off = main_foff + text_va
                                # But .text might span multiple memory ranges
                                # Read what we can from this range first
                                remaining_in_range = start + size - (main_base + text_va)
                                readable = min(text_vsize, remaining_in_range)
                                print(f"  Readable from this range: {readable/1048576:.1f}MB (of {text_vsize/1048576:.1f}MB)")
                                
                                f.seek(text_file_off)
                                text_data = f.read(readable)
                                
                                # Check code quality
                                prologues = text_data[:0x100000].count(b'\x48\x89\x5c\x24')
                                print(f"  Prologues in 1st MB: {prologues}")
                                
                                # Save
                                out_path = os.path.join(OUT, "main_text_decrypted.bin")
                                with open(out_path, "wb") as f2:
                                    f2.write(text_data)
                                print(f"  Saved {len(text_data)/1048576:.1f}MB to {out_path}")
                                
                                # If .text spans multiple ranges, read more
                                if readable < text_vsize:
                                    # Find next range
                                    text_end = main_base + text_va + text_vsize
                                    print(f"\n  .text spans beyond first range. Reading remaining...")
                                    full_text = bytearray(text_data)
                                    for s2, sz2, fo2 in ranges:
                                        if s2 > main_base + text_va and s2 < text_end:
                                            # This range is within .text
                                            f.seek(fo2)
                                            chunk = f.read(min(sz2, text_end - s2))
                                            full_text.extend(chunk)
                                            print(f"    Added range 0x{s2:x} +0x{sz2:x} -> {len(chunk)/1048576:.1f}MB")
                                    
                                    # Save full
                                    with open(out_path, "wb") as f2:
                                        f2.write(bytes(full_text))
                                    print(f"  Total .text: {len(full_text)/1048576:.1f}MB saved to {out_path}")
                                    
                                    # Check the full data
                                    prologues_total = bytes(full_text)[:0x100000].count(b'\x48\x89\x5c\x24')
                                    print(f"  Prologues in 1st MB (total): {prologues_total}")
                                    
                                    # Also check around offset 0x3DB000 (where we saw real code)
                                    if len(full_text) > 0x3DB000:
                                        chunk_at_3db = bytes(full_text[0x3DB000:0x3DB000+0x100000])
                                        prol_3db = chunk_at_3db.count(b'\x48\x89\x5c\x24')
                                        print(f"  Prologues at offset 0x3DB000: {prol_3db}")
                    break
            break
