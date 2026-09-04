#!/usr/bin/env python3
"""
Battle.net 2 Protocol Decoder
==============================
Reads a pcap + SSLKEYLOGFILE, reassembles TLS/WebSocket streams on port 1119,
and decodes BNet2 RPC frames.

Wire format (inside each WebSocket binary frame):
  [2 bytes BE: header_len] [header_len bytes: protobuf Header] [header.size bytes: protobuf body]

Header protobuf schema (bnet.protocol era used by SC2):
  field 1 uint32: service_id  (0xFE = response)
  field 2 uint32: method_id
  field 3 uint32: token       (request/response correlation)
  field 4 uint64: object_id
  field 5 uint32: size        (body byte length)
  field 6 uint32: status      (error code on responses)
  field 11 fixed32: service_hash (FNV-1a of service name, modern clients)

Known service hashes:
  0x65446991  ConnectionService
  0x0DECFC01  AuthenticationService
  0x62DA0891  AccountService
  0x3FC1274D  GameUtilitiesService   ← SC2 arcade lobby commands live here
  0xFA0796FF  PresenceService
  0xA3DDB1BD  FriendsService

Usage:
    python3 bnet_decoder.py <capture.pcapng> <keylog.txt>
    python3 bnet_decoder.py <capture.pcapng> <keylog.txt> --verbose

Requires: tshark (apt install tshark), pyshark (pip install pyshark)
"""
import sys, struct, argparse, json, zlib
from pathlib import Path

# ── known constants ───────────────────────────────────────────────────────────

SERVICE_NAMES = {
    0x65446991: "ConnectionService",
    0x0DECFC01: "AuthenticationService",
    0x62DA0891: "AccountService",
    0x3FC1274D: "GameUtilitiesService",
    0xFA0796FF: "PresenceService",
    0xA3DDB1BD: "FriendsService",
}

METHOD_NAMES = {
    0x65446991: {1:"Connect", 2:"Bind", 3:"Echo", 4:"ForceDisconnect", 5:"KeepAlive", 6:"Encrypt"},
    0x0DECFC01: {1:"Logon", 2:"ModuleNotify", 3:"ModuleMessage", 5:"GenerateSSOToken",
                 6:"SelectGameAccount", 7:"VerifyWebCredentials", 8:"GenerateWebCredentials"},
    0x62DA0891: {13:"ResolveAccount", 25:"Subscribe", 30:"GetAccountState", 32:"GetLicenses"},
    0x3FC1274D: {1:"ProcessClientRequest", 2:"PresenceChannelCreated", 6:"ProcessServerRequest",
                 7:"OnGameAccountOnline", 8:"OnGameAccountOffline", 10:"GetAllValuesForAttribute"},
}

RESPONSE_SERVICE_ID = 0xFE


# ── protobuf varint ───────────────────────────────────────────────────────────

def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    result, shift = 0, 0
    while offset < len(data):
        b = data[offset]; offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7
    return result, offset


def parse_proto_fields(data: bytes) -> dict:
    """
    Minimal protobuf parser. Returns {field_number: [values...]}.
    Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
    """
    fields: dict[int, list] = {}
    offset = 0
    while offset < len(data):
        try:
            tag, offset = read_varint(data, offset)
            field_num  = tag >> 3
            wire_type  = tag & 0x07
            if wire_type == 0:
                val, offset = read_varint(data, offset)
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 1:
                val = struct.unpack_from("<Q", data, offset)[0]; offset += 8
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 2:
                length, offset = read_varint(data, offset)
                val = data[offset:offset + length]; offset += length
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 5:
                val = struct.unpack_from("<I", data, offset)[0]; offset += 4
                fields.setdefault(field_num, []).append(val)
            else:
                break
        except Exception:
            break
    return fields


def parse_header(data: bytes) -> dict:
    f = parse_proto_fields(data)
    hdr = {
        "service_id":   f.get(1,  [None])[0],
        "method_id":    f.get(2,  [None])[0],
        "token":        f.get(3,  [None])[0],
        "size":         f.get(5,  [0])[0] or 0,
        "status":       f.get(6,  [0])[0] or 0,
        "service_hash": f.get(11, [None])[0],
    }
    return hdr


# ── attribute bag parser (GameUtilities payload) ──────────────────────────────

def try_decode_blob(blob: bytes) -> str | None:
    """
    BNet2 blobs: [4 bytes LE: length+1] [zlib(TypeName:JSON\0)]
    """
    try:
        if len(blob) < 5:
            return None
        declared_len = struct.unpack_from("<I", blob, 0)[0]
        compressed   = blob[4:]
        decompressed = zlib.decompress(compressed)
        text = decompressed.rstrip(b"\x00").decode("utf-8", errors="replace")
        return text
    except Exception:
        return None


def parse_attributes(body: bytes) -> list[dict]:
    """
    Parse a GameUtilities ClientRequest/ClientResponse body.
    Field 1 = repeated Attribute { field 1 = name (string), field 2 = Variant }
    Variant: field 5 = string_value, field 6 = blob_value, field 9 = uint_value
    """
    attrs = []
    top = parse_proto_fields(body)
    for raw_attr in top.get(1, []):
        if not isinstance(raw_attr, bytes):
            continue
        af = parse_proto_fields(raw_attr)
        name = af.get(1, [b""])[0]
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")

        value_raw = af.get(2, [b""])[0]
        value_str = None
        if isinstance(value_raw, bytes) and value_raw:
            vf = parse_proto_fields(value_raw)
            if 5 in vf:   # string_value
                value_str = vf[5][0].decode("utf-8", errors="replace") if isinstance(vf[5][0], bytes) else str(vf[5][0])
            elif 6 in vf: # blob_value
                decoded = try_decode_blob(vf[6][0])
                value_str = decoded if decoded else f"<blob {len(vf[6][0])} bytes>"
            elif 9 in vf: # uint_value
                value_str = str(vf[9][0])
            elif 3 in vf: # int_value
                value_str = str(vf[3][0])

        attrs.append({"name": name, "value": value_str})
    return attrs


# ── WebSocket frame parser ────────────────────────────────────────────────────

def parse_ws_frames(stream: bytes) -> list[bytes]:
    """
    Extract binary WebSocket frame payloads from a reassembled TLS stream.
    Skips the HTTP upgrade handshake at the start.
    """
    payloads = []

    # Skip HTTP upgrade handshake (ends with \r\n\r\n)
    http_end = stream.find(b"\r\n\r\n")
    if http_end == -1:
        return payloads

    # Server response also ends with \r\n\r\n - find the second one
    second = stream.find(b"\r\n\r\n", http_end + 4)
    offset = (second + 4) if second != -1 else (http_end + 4)

    while offset + 2 <= len(stream):
        try:
            b0 = stream[offset]
            b1 = stream[offset + 1]
            # fin    = (b0 >> 7) & 1
            opcode = b0 & 0x0F
            masked = (b1 >> 7) & 1
            plen   = b1 & 0x7F

            header_size = 2
            if plen == 126:
                if offset + 4 > len(stream): break
                plen = struct.unpack_from(">H", stream, offset + 2)[0]
                header_size = 4
            elif plen == 127:
                if offset + 10 > len(stream): break
                plen = struct.unpack_from(">Q", stream, offset + 2)[0]
                header_size = 10

            if masked:
                header_size += 4

            total = header_size + plen
            if offset + total > len(stream):
                break

            if opcode == 2:  # binary frame
                payload = stream[offset + header_size:offset + total]
                if masked:
                    mask = stream[offset + header_size - 4:offset + header_size]
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                payloads.append(payload)

            offset += total
        except Exception:
            break

    return payloads


# ── BNet2 frame parser ────────────────────────────────────────────────────────

def parse_bnet_frames(ws_payload: bytes) -> list[tuple[dict, bytes]]:
    """
    Parse BNet2 frames from a WebSocket binary payload.
    Returns list of (header_dict, body_bytes).
    """
    frames = []
    offset = 0
    while offset + 2 <= len(ws_payload):
        header_len = struct.unpack_from(">H", ws_payload, offset)[0]
        offset += 2
        if offset + header_len > len(ws_payload):
            break
        hdr_bytes = ws_payload[offset:offset + header_len]
        offset   += header_len
        hdr      = parse_header(hdr_bytes)
        body_len = hdr.get("size", 0)

        # SC2 requests often omit the size field (body_len == 0).
        # When that happens, check if the remaining bytes look like a new
        # BNet2 frame (valid 2-byte header_len that fits in the payload).
        # If not, treat them as the body of this frame.
        if body_len == 0 and offset < len(ws_payload):
            remaining = len(ws_payload) - offset
            if remaining >= 2:
                peek_hlen = struct.unpack_from(">H", ws_payload, offset)[0]
                next_frame_fits = (peek_hlen > 0 and peek_hlen <= 256
                                   and offset + 2 + peek_hlen <= len(ws_payload))
            else:
                next_frame_fits = False
            if not next_frame_fits:
                body_len = remaining

        body    = ws_payload[offset:offset + body_len]
        offset += body_len
        frames.append((hdr, body))
    return frames


# ── main ──────────────────────────────────────────────────────────────────────

def describe_frame(hdr: dict, body: bytes, direction: str) -> str:
    sid   = hdr.get("service_id")
    mid   = hdr.get("method_id")
    shash = hdr.get("service_hash")
    tok   = hdr.get("token")

    if sid == RESPONSE_SERVICE_ID:
        label = f"RESPONSE tok={tok} status={hdr.get('status', 0)}"
    else:
        sname = SERVICE_NAMES.get(shash, f"svc={sid:#x}/hash={shash:#010x}" if shash else f"svc={sid}")
        mname = (METHOD_NAMES.get(shash) or {}).get(mid, f"method={mid}")
        label = f"{sname}.{mname} tok={tok}"

    parts = [f"  [{direction}] {label}  body={len(body)}b"]

    # If GameUtilities, try to decode attribute bag
    if shash == 0x3FC1274D:
        attrs = parse_attributes(body)
        if attrs:
            for a in attrs:
                parts.append(f"    attr: {a['name']} = {a['value']}")

    # If response or any body, try generic string extraction
    elif body:
        try:
            f = parse_proto_fields(body)
            for fnum, vals in sorted(f.items()):
                for v in vals:
                    if isinstance(v, bytes):
                        try:
                            s = v.decode("utf-8")
                            if len(s) > 3 and s.isprintable():
                                parts.append(f"    field[{fnum}]: {s!r}")
                        except Exception:
                            pass
        except Exception:
            pass

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="BNet2 protocol decoder")
    parser.add_argument("pcap",    help="Path to pcap/pcapng file")
    parser.add_argument("keylog",  help="Path to SSLKEYLOGFILE")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all frames, not just GameUtilities")
    args = parser.parse_args()

    if not Path(args.keylog).exists():
        print(f"[!] Keylog not found: {args.keylog}")
        print("    Launch SC2 via Lutris BEFORE starting capture next time.")
        sys.exit(1)

    print(f"[+] Pcap:   {args.pcap}")
    print(f"[+] Keylog: {args.keylog}")
    print()

    # Use tshark to extract decrypted TLS stream bytes per TCP stream
    import subprocess
    result = subprocess.run([
        "tshark", "-r", args.pcap,
        "-d", "tcp.port==1119,tls",
        "-o", f"tls.keylog_file:{Path(args.keylog).resolve()}",
        "-z", "follow,tls,hex,0",
        "-q"
    ], capture_output=True, text=True)

    # Find all decryptable streams by trying each one
    # First get stream IDs
    id_result = subprocess.run([
        "tshark", "-r", args.pcap,
        "-d", "tcp.port==1119,tls",
        "-o", f"tls.keylog_file:{Path(args.keylog).resolve()}",
        "-Y", "tcp.port==1119",
        "-T", "fields", "-e", "tcp.stream"
    ], capture_output=True, text=True)

    stream_ids = sorted(set(id_result.stdout.strip().splitlines()))
    print(f"[+] Found {len(stream_ids)} TCP streams on port 1119: {stream_ids}")
    print()

    for sid in stream_ids:
        follow = subprocess.run([
            "tshark", "-r", args.pcap,
            "-d", "tcp.port==1119,tls",
            "-o", f"tls.keylog_file:{Path(args.keylog).resolve()}",
            "-z", f"follow,tls,hex,{sid}",
            "-q"
        ], capture_output=True, text=True)

        lines = follow.stdout.splitlines()

        # Find node lines to get addresses
        nodes = [l for l in lines if l.startswith("Node")]
        if len(nodes) >= 2 and ":0" in nodes[0]:
            print(f"  stream {sid}: could not decrypt (no handshake captured)")
            continue

        # Parse hex dump: lines like "00000000  47 45 54 ..."
        # tshark follow hex output alternates client/server blocks prefixed with tab
        node0_data = bytearray()
        node1_data = bytearray()

        for line in lines:
            # tshark follow,tls,hex interleaved format:
            #   no-tab hex lines  = Node 0 (client → server)
            #   tab-indented hex  = Node 1 (server → client)
            is_tabbed = line.startswith("\t")
            parts = line.strip().split()
            if parts and len(parts[0]) == 8:
                try:
                    int(parts[0], 16)  # valid hex offset
                    hex_bytes = parts[1:17]
                    raw = bytes(int(h, 16) for h in hex_bytes if len(h) == 2)
                    if is_tabbed:
                        node1_data += raw
                    else:
                        node0_data += raw
                except ValueError:
                    pass

        if not node0_data and not node1_data:
            print(f"  stream {sid}: no data")
            continue

        addr0 = nodes[0].split(": ")[-1] if nodes else "client"
        addr1 = nodes[1].split(": ")[-1] if nodes else "server"
        print(f"[stream {sid}] {addr0} ↔ {addr1}")
        print(f"  client→server: {len(node0_data)} bytes | server→client: {len(node1_data)} bytes")

        for direction, data in [("C→S", bytes(node0_data)), ("S→C", bytes(node1_data))]:
            if not data:
                continue

            # Check if this looks like WebSocket (starts with HTTP GET or HTTP/1.1)
            if data[:4] in (b"GET ", b"HTTP"):
                ws_frames = parse_ws_frames(data)
                print(f"  {direction}: WebSocket stream — {len(ws_frames)} binary frames")
                for i, frame in enumerate(ws_frames):
                    bnet_frames = parse_bnet_frames(frame)
                    for hdr, body in bnet_frames:
                        shash = hdr.get("service_hash")
                        is_gameutils = shash == 0x3FC1274D
                        if is_gameutils or args.verbose:
                            print(describe_frame(hdr, body, direction))
            else:
                # Raw BNet2 (no WebSocket wrapper) — try direct parse
                bnet_frames = parse_bnet_frames(data)
                print(f"  {direction}: raw BNet2 — {len(bnet_frames)} frames")
                for hdr, body in bnet_frames:
                    shash = hdr.get("service_hash")
                    is_gameutils = shash == 0x3FC1274D
                    if is_gameutils or args.verbose:
                        print(describe_frame(hdr, body, direction))

        print()


if __name__ == "__main__":
    main()
