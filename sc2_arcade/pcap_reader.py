"""
PCAP / Journal Reader
=====================
Two data sources for the lobby tracker:

  1. pcap_reader  — reads a .pcapng file and extracts cleartext signal lines
                    from the SC2 traffic (works on port 80 depot traffic;
                    port 1119 TLS traffic is opaque without session keys).

  2. journal_reader — reads a sc2-arcade-watcher style journal file from disk
                      (line-delimited CRLF text files written by a runner).

  3. sslkeylog_reader — reads a Wireshark SSLKEYLOGFILE alongside a pcap to
                        decrypt the port 1119 TLS and extract lobby signals.
                        Requires pyshark + tshark.
"""

from __future__ import annotations

import struct
import socket
import logging
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Journal file reader (sc2-arcade-watcher format)
# ---------------------------------------------------------------------------

def read_journal_file(path: str | Path) -> Iterator[str]:
    """
    Yield signal lines from a sc2-arcade-watcher journal file.
    Files are numbered (e.g. 0001, 0002) and contain CRLF-terminated lines
    in the format:  KIND:VERSION\x01TIMESTAMP\x01FIELDS...
    """
    path = Path(path)
    if path.is_dir():
        files = sorted(path.glob("*"), key=lambda p: p.name)
        for f in files:
            yield from _read_journal_lines(f)
    else:
        yield from _read_journal_lines(path)


def _read_journal_lines(path: Path) -> Iterator[str]:
    log.info(f"Reading journal: {path}")
    with open(path, "rb") as f:
        buf = b""
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                yield line.decode("utf-8", errors="replace")
        if buf:
            yield buf.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# PCAP reader (minimal, no external libs)
# Reads pcapng files and extracts HTTP bodies from port 80 traffic.
# Port 1119 (TLS) content cannot be decrypted without session keys.
# ---------------------------------------------------------------------------

PCAPNG_BLOCK_SHB  = 0x0A0D0D0A  # Section Header Block
PCAPNG_BLOCK_IHB  = 0x00000001  # Interface Description Block
PCAPNG_BLOCK_EPB  = 0x00000006  # Enhanced Packet Block
PCAPNG_BLOCK_SPB  = 0x00000003  # Simple Packet Block

PCAP_MAGIC_LE     = 0xA1B2C3D4
PCAP_MAGIC_BE     = 0xD4C3B2A1


def _read_pcap_packets(path: str | Path) -> Iterator[bytes]:
    """
    Minimal pcap reader (classic format, little-endian).
    Yields raw packet bytes (full Ethernet frame).
    """
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            raise ValueError(f"Not a pcap file (magic={magic:#010x})")
        be = magic == PCAP_MAGIC_BE
        endian = ">" if be else "<"
        f.read(20)  # skip rest of global header (ver, zone, sigfigs, snaplen, dlt)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl_len)
            yield data


def _read_pcapng_packets(path: str | Path) -> Iterator[tuple[bytes, int]]:
    """
    Minimal pcapng reader. Yields (raw_packet_bytes, link_type) tuples.
    link_type: 0=BSD loopback, 1=Ethernet, 228=IPv4 raw, 101=raw
    """
    link_type = 1  # default: Ethernet
    with open(path, "rb") as f:
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            body_len = block_len - 12  # type(4) + len(4) + trailing_len(4)
            body = f.read(body_len)
            f.read(4)  # trailing block length

            if block_type == PCAPNG_BLOCK_IHB:
                # IDB: link_type is first 2 bytes
                if len(body) >= 2:
                    link_type = struct.unpack("<H", body[:2])[0]

            elif block_type == PCAPNG_BLOCK_EPB:
                # interface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4) = 20 bytes
                if len(body) < 20:
                    continue
                cap_len = struct.unpack("<I", body[12:16])[0]
                pkt_data = body[20:20 + cap_len]
                yield pkt_data, link_type


def _extract_ipv4_tcp_payload(frame: bytes,
                              link_type: int = 1) -> tuple[bytes, int, int] | None:
    """
    Extract TCP payload, supporting multiple link-layer types.
    Returns (payload, src_port, dst_port) or None.

    link_type:
      0   — BSD/macOS NULL loopback (4-byte protocol family prefix)
      1   — Ethernet
      101 — Raw IPv4
      228 — Raw IPv4
    """
    if link_type == 1:                   # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800:
            return None
        ip = frame[14:]

    elif link_type == 0:                 # BSD loopback (macOS)
        if len(frame) < 4:
            return None
        # 4-byte protocol family (little-endian on macOS); 2 = AF_INET (IPv4)
        proto_family = struct.unpack("<I", frame[:4])[0]
        if proto_family != 2:
            return None
        ip = frame[4:]

    elif link_type in (101, 228):        # Raw IPv4
        ip = frame

    else:
        return None

    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    if proto != 6:                       # TCP only
        return None

    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    src_port = struct.unpack(">H", tcp[0:2])[0]
    dst_port = struct.unpack(">H", tcp[2:4])[0]
    data_off = ((tcp[12] >> 4) * 4)
    payload  = tcp[data_off:]
    return payload, src_port, dst_port


def _iter_packets(path: Path):
    """Yield (frame_bytes, link_type) for every packet in a pcap/pcapng."""
    suffix = path.suffix.lower()
    if suffix in (".pcapng", ".npcapng"):
        yield from _read_pcapng_packets(path)
    else:
        for pkt in _read_pcap_packets(path):
            yield pkt, 1   # classic pcap defaults to Ethernet


def extract_http_bodies(pcap_path: str | Path, target_port: int = 80) -> Iterator[bytes]:
    """
    Yield HTTP response bodies from a pcap/pcapng file for the given port.
    Only works on cleartext HTTP (port 80).  Port 1119 (TLS) is opaque.
    """
    path = Path(pcap_path)
    try:
        for frame, link_type in _iter_packets(path):
            result = _extract_ipv4_tcp_payload(frame, link_type)
            if not result:
                continue
            payload, src_port, dst_port = result
            if not payload or src_port != target_port:
                continue
            try:
                text = payload.decode("utf-8", errors="ignore")
                if text.startswith("HTTP/"):
                    if "\r\n\r\n" in text:
                        _, body = text.split("\r\n\r\n", 1)
                        if body:
                            yield body.encode()
                else:
                    yield payload
            except Exception:
                pass
    except Exception as e:
        log.error(f"Could not read pcap: {e}")


def describe_pcap(pcap_path: str | Path) -> dict:
    """
    Summarise the connections in a pcap file.
    Returns a dict with (src_port, dst_port) → packet counts.
    """
    path  = Path(pcap_path)
    flows: dict[tuple, int] = {}
    try:
        for frame, link_type in _iter_packets(path):
            result = _extract_ipv4_tcp_payload(frame, link_type)
            if not result:
                continue
            _, src_port, dst_port = result
            key = (src_port, dst_port)
            flows[key] = flows.get(key, 0) + 1
    except Exception as e:
        log.error(f"describe_pcap error: {e}")
    return dict(sorted(flows.items(), key=lambda x: -x[1]))
