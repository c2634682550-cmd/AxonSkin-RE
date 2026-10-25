"""Parse pcapng without scapy: extract TCP streams and DNS queries from raw bytes.
pcapng format: Section Header Block (0x0A0D0D0A), Interface Description Block (0x1),
Enhanced Packet Block (0x6), etc. Link layer is likely Ethernet (1) or Raw (101)."""
import struct, os

pcap = r"C:\Users\26346\AppData\Local\Temp\axon_auth\auth.pcapng"
data = open(pcap,"rb").read()
print(f"file size: {len(data)}")

# pcapng block structure: block_type(4) block_total_length(4) body... block_total_length(4)
off = 0
blocks = []
while off < len(data) - 12:
    bt = struct.unpack_from("<I", data, off)[0]
    bl = struct.unpack_from("<I", data, off+4)[0]
    if bl < 12 or bl > len(data) - off:
        # try next byte
        off += 1
        continue
    blocks.append((bt, off, bl))
    off += bl  # aligned to 4

print(f"blocks: {len(blocks)}")
# parse section header to get byte order
bom = struct.unpack_from("<I", data, 28)[0]  # byte order magic
print(f"byte order magic: 0x{bom:x} (expect 0x1A2B3C4D)")

# Enhanced Packet Block (0x6): interface_id(4) ts_high(4) ts_low(4) captured_len(4) orig_len(4) packet_data...
# Interface Description Block (0x1): link_type(2) reserved(2) snap_len(4) ...
link_type = 1  # default Ethernet
packets = []
for (bt, boff, bl) in blocks:
    if bt == 0x1:  # IDB
        lt = struct.unpack_from("<H", data, boff+8)[0]
        link_type = lt
    elif bt == 0x6:  # EPB
        iface = struct.unpack_from("<I", data, boff+8)[0]
        caplen = struct.unpack_from("<I", data, boff+20)[0]
        pkt = data[boff+28:boff+28+caplen]
        packets.append(pkt)

print(f"link_type: {link_type} packets: {len(packets)}")

# Parse Ethernet/IP/TCP/UDP
for i, pkt in enumerate(packets):
    if link_type == 1:  # Ethernet
        if len(pkt) < 14: continue
        eth_type = struct.unpack_from(">H", pkt, 12)[0]
        if eth_type != 0x0800: continue  # not IPv4
        ip_off = 14
    elif link_type == 101:  # Raw IP
        ip_off = 0
    else:
        ip_off = 0  # try raw
    
    if ip_off + 20 > len(pkt): continue
    ip_ver = (pkt[ip_off] >> 4) & 0xF
    if ip_ver != 4: continue
    ip_ihl = (pkt[ip_off] & 0xF) * 4
    ip_proto = pkt[ip_off+9]
    ip_src = ".".join(str(b) for b in pkt[ip_off+12:ip_off+16])
    ip_dst = ".".join(str(b) for b in pkt[ip_off+16:ip_off+20])
    ip_total_len = struct.unpack_from(">H", pkt, ip_off+2)[0]
    
    transport_off = ip_off + ip_ihl
    
    if ip_proto == 6:  # TCP
        if transport_off + 20 > len(pkt): continue
        sport = struct.unpack_from(">H", pkt, transport_off)[0]
        dport = struct.unpack_from(">H", pkt, transport_off+2)[0]
        data_off = (pkt[transport_off+12] >> 4) * 4
        payload_off = transport_off + data_off
        payload = pkt[payload_off:ip_off+ip_total_len]
        if len(payload) > 0:
            txt = payload.decode('utf-8','replace')[:300]
            print(f"[{i}] TCP {ip_src}:{sport} -> {ip_dst}:{dport} ({len(payload)}b)")
            print(f"     {txt}")
            print()
    elif ip_proto == 17:  # UDP
        if transport_off + 8 > len(pkt): continue
        sport = struct.unpack_from(">H", pkt, transport_off)[0]
        dport = struct.unpack_from(">H", pkt, transport_off+2)[0]
        ulen = struct.unpack_from(">H", pkt, transport_off+4)[0]
        payload = pkt[transport_off+8:transport_off+8+ulen-8]
        if dport == 53 and len(payload) > 12:
            # DNS query
            qname = []
            di = 12
            while di < len(payload) and payload[di] != 0:
                l = payload[di]; di += 1
                qname.append(payload[di:di+l].decode('ascii','replace')); di += l
            qn = ".".join(qname)
            print(f"[{i}] DNS {ip_src}:{sport} -> {ip_dst}:{dport} query: {qn}")
        elif len(payload) > 0:
            txt = payload.decode('utf-8','replace')[:200]
            print(f"[{i}] UDP {ip_src}:{sport} -> {ip_dst}:{dport} ({len(payload)}b) {txt}")
