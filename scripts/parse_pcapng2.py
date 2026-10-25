"""Parse pcapng - fixed encoding. Extract all TCP streams to the auth server."""
import struct, os, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

pcap = r"C:\Users\26346\AppData\Local\Temp\axon_auth\auth.pcapng"
data = open(pcap,"rb").read()

off = 0; blocks = []
while off < len(data) - 12:
    bt = struct.unpack_from("<I", data, off)[0]
    bl = struct.unpack_from("<I", data, off+4)[0]
    if bl < 12 or bl > len(data) - off:
        off += 1; continue
    blocks.append((bt, off, bl)); off += bl

packets = []
for (bt, boff, bl) in blocks:
    if bt == 0x6:
        caplen = struct.unpack_from("<I", data, boff+20)[0]
        pkt = data[boff+28:boff+28+caplen]
        packets.append(pkt)

print(f"packets: {len(packets)}")
streams = {}
for i, pkt in enumerate(packets):
    if len(pkt) < 34: continue
    eth_type = struct.unpack_from(">H", pkt, 12)[0]
    if eth_type != 0x0800: continue
    ip_off = 14
    if ip_off + 20 > len(pkt): continue
    ip_ihl = (pkt[ip_off] & 0xF) * 4
    ip_proto = pkt[ip_off+9]
    ip_src = ".".join(str(b) for b in pkt[ip_off+12:ip_off+16])
    ip_dst = ".".join(str(b) for b in pkt[ip_off+16:ip_off+20])
    ip_total_len = struct.unpack_from(">H", pkt, ip_off+2)[0]
    toff = ip_off + ip_ihl
    if ip_proto == 6:  # TCP
        if toff + 20 > len(pkt): continue
        sport = struct.unpack_from(">H", pkt, toff)[0]
        dport = struct.unpack_from(">H", pkt, toff+2)[0]
        doff = (pkt[toff+12] >> 4) * 4
        payload = pkt[toff+doff:ip_off+ip_total_len]
        key = (ip_src, sport, ip_dst, dport)
        if len(payload) > 0:
            streams.setdefault(key, bytearray()).extend(payload)
            # print hex + printable
            printable = ''.join(chr(b) if 32<=b<=126 else '.' for b in payload)
            print(f"[{i}] TCP {ip_src}:{sport} -> {ip_dst}:{dport} {len(payload)}b")
            print(f"     hex: {payload.hex()}")
            print(f"     asc: {printable}")
    elif ip_proto == 17:
        if toff + 8 > len(pkt): continue
        sport = struct.unpack_from(">H", pkt, toff)[0]
        dport = struct.unpack_from(">H", pkt, toff+2)[0]
        ulen = struct.unpack_from(">H", pkt, toff+4)[0]
        payload = pkt[toff+8:toff+8+ulen-8]
        if dport == 53 and len(payload) > 12:
            qname = []; di = 12
            while di < len(payload) and payload[di] != 0:
                l = payload[di]; di += 1
                qname.append(payload[di:di+l].decode('ascii','replace')); di += l
            print(f"[{i}] DNS {ip_src}:{sport} -> {ip_dst}:{dport} query: {'.'.join(qname)}")
        elif len(payload) > 0:
            printable = ''.join(chr(b) if 32<=b<=126 else '.' for b in payload)
            print(f"[{i}] UDP {ip_src}:{sport} -> {ip_dst}:{dport} {len(payload)}b {printable}")

print("\n=== Reassembled TCP streams ===")
for key, payload in streams.items():
    src_ip, src_port, dst_ip, dst_port = key
    print(f"\n{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({len(payload)}b total)")
    print(f"  hex: {bytes(payload).hex()}")
    printable = ''.join(chr(b) if 32<=b<=126 else '.' for b in payload)
    print(f"  asc: {printable}")
