"""Find all memory ranges that fall within the .text section (VA 0x1000 - 0x261480d).
Main module base: 0x7ff78e700000
.text: VA=0x1000, VSize=0x0261380d
.text start: 0x7ff78e701000, end: 0x7ff78ed1480d
Also check .rdata (VA=0x2615000, VSize=0x15ed084):
  start: 0x7ff78e915000, end: 0x7ff78ea722084
"""
import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

md_file = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6\full.dmp"
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack6"

main_base = 0x7ff78e700000
text_start = main_base + 0x1000
text_end = main_base + 0x1000 + 0x0261380d  # 0x7ff78e701000 - 0x7ff78ed1480d
rdata_start = main_base + 0x2615000
rdata_end = main_base + 0x2615000 + 0x15ed084

print(f".text range: 0x{text_start:x} - 0x{text_end:x} ({(text_end-text_start)/1048576:.1f}MB)")
print(f".rdata range: 0x{rdata_start:x} - 0x{rdata_end:x} ({(rdata_end-rdata_start)/1048576:.1f}MB)")

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
            
            cur_offset = base_rva
            all_ranges = []
            for j in range(num_ranges):
                start = struct.unpack_from('<Q', f.read(8))[0]
                size = struct.unpack_from('<Q', f.read(8))[0]
                all_ranges.append((start, size, cur_offset))
                cur_offset += size
            
            # Find ranges overlapping .text
            text_ranges = []
            print(f"\n=== Ranges overlapping .text ===")
            for start, size, foff in all_ranges:
                if start < text_end and start + size > text_start:
                    overlap_start = max(start, text_start)
                    overlap_end = min(start + size, text_end)
                    overlap_size = overlap_end - overlap_start
                    text_ranges.append((overlap_start, overlap_size, foff + (overlap_start - start)))
                    print(f"  0x{start:016x} +0x{size:08x} -> overlap 0x{overlap_start:x} +0x{overlap_size:x} (file 0x{foff + (overlap_start-start):x})")
            
            print(f"\n  Total overlapping ranges: {len(text_ranges)}")
            total_text = sum(s for _, s, _ in text_ranges)
            print(f"  Total .text coverage: {total_text/1048576:.1f}MB (of 38.1MB)")
            
            # Extract .text
            if text_ranges:
                text_data = bytearray()
                for start, size, foff in text_ranges:
                    f.seek(foff)
                    chunk = f.read(size)
                    text_data.extend(chunk)
                
                out_path = os.path.join(OUT, "main_text_decrypted.bin")
                with open(out_path, "wb") as f2:
                    f2.write(bytes(text_data))
                print(f"\n  Saved .text: {len(text_data)/1048576:.1f}MB to {out_path}")
                
                # Verify code quality
                prologues = bytes(text_data)[:0x100000].count(b'\x48\x89\x5c\x24')
                print(f"  Prologues in 1st MB: {prologues}")
                
                # Check every MB
                for i in range(0, min(len(text_data), 0x2600000), 0x100000):
                    chunk = bytes(text_data[i:i+0x100000])
                    if len(chunk) == 0:
                        break
                    prol = chunk.count(b'\x48\x89\x5c\x24')
                    if prol > 20:
                        print(f"    offset 0x{i:x} ({i//1048576}MB): {prol} prologues")
            
            # Find ranges overlapping .rdata
            rdata_ranges = []
            print(f"\n=== Ranges overlapping .rdata ===")
            for start, size, foff in all_ranges:
                if start < rdata_end and start + size > rdata_start:
                    overlap_start = max(start, rdata_start)
                    overlap_end = min(start + size, rdata_end)
                    overlap_size = overlap_end - overlap_start
                    rdata_ranges.append((overlap_start, overlap_size, foff + (overlap_start - start)))
            
            if rdata_ranges:
                rdata_data = bytearray()
                for start, size, foff in rdata_ranges:
                    f.seek(foff)
                    chunk = f.read(size)
                    rdata_data.extend(chunk)
                
                out_path2 = os.path.join(OUT, "main_rdata_decrypted.bin")
                with open(out_path2, "wb") as f2:
                    f2.write(bytes(rdata_data))
                print(f"  Saved .rdata: {len(rdata_data)/1048576:.1f}MB to {out_path2}")
                
                # Check for strings
                import re
                strings = re.findall(rb'[\x20-\x7e]{10,}', bytes(rdata_data)[:0x100000])
                print(f"  ASCII strings in 1st MB: {len(strings)}")
                for s in strings[:10]:
                    print(f"    {s.decode('ascii','replace')}")
            
            break
