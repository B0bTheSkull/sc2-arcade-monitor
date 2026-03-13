"""
Battle.net 2.0 Protocol Client for SC2 Arcade Lobby Data
=========================================================

Protocol overview (reverse-engineered from sc2-arcade-watcher + community docs):

  Transport : TLS 1.2+ over TCP port 1119
  Encoding  : Length-prefixed protobuf frames
  Auth      : SRP6-based challenge/response with real Battle.net credentials

Frame format (after TLS):
  [2 bytes big-endian] header_length
  [header_length bytes] BnetProto.Header  (protobuf)
  [header.size bytes]   body              (protobuf, service-specific)

Key services (from HearthSim / community reverse-engineering):
  service_id 0  — connection service (built-in)
  service_id 1  — authentication service
  service_id 6  — game master / lobby service
  service_id 11 — presence service

SC2-specific lobby listing uses the GameMasterService:
  method 1 — GetGameList / ListAvailableGames

NOTE: This client requires a REAL Battle.net account (email + password), not
just OAuth API keys.  The API keys only grant access to the public REST API.
For testing without credentials use the pcap_reader or journal_reader modes.

Architecture: the runner sends lobby-feed text signals over the established
connection.  We translate those signals to the lobby tracker.
"""

from __future__ import annotations

import ssl
import socket
import struct
import threading
import time
import logging
from typing import Optional, Callable

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Minimal protobuf helpers (no external protobuf lib required for framing)
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as protobuf varint."""
    buf = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Return (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


# ---------------------------------------------------------------------------
# Minimal hand-rolled BnetProto.Header encoder
# We only need a subset of fields.
#
# Header proto (simplified):
#   message Header {
#     uint32 service_id   = 1;
#     uint32 method_id    = 2;
#     uint32 token        = 3;
#     uint64 object_id    = 4;
#     uint32 size         = 5;
#     uint32 status       = 6;
#     ...
#   }
# ---------------------------------------------------------------------------

def _proto_field(field_num: int, wire_type: int, value: int) -> bytes:
    tag = (field_num << 3) | wire_type
    return _encode_varint(tag) + _encode_varint(value)


def _encode_header(service_id: int, method_id: int, token: int,
                   body_size: int, object_id: int = 0) -> bytes:
    hdr = b""
    hdr += _proto_field(1, 0, service_id)    # varint field
    hdr += _proto_field(2, 0, method_id)
    hdr += _proto_field(3, 0, token)
    if object_id:
        hdr += _proto_field(4, 0, object_id)
    hdr += _proto_field(5, 0, body_size)
    return hdr


def _encode_frame(service_id: int, method_id: int, token: int,
                  body: bytes, object_id: int = 0) -> bytes:
    header = _encode_header(service_id, method_id, token,
                            len(body), object_id)
    return struct.pack(">H", len(header)) + header + body


def _decode_header(data: bytes) -> dict:
    """Parse a BnetProto.Header protobuf into a dict."""
    result = {}
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:   # varint
            val, pos = _decode_varint(data, pos)
            result[field_num] = val
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            result[field_num] = data[pos:pos + length]
            pos += length
        else:
            break  # unsupported wire type, stop
    return result


# ---------------------------------------------------------------------------
# Connection state
# ---------------------------------------------------------------------------

BNET_HOST_US = "us.actual.battle.net"
BNET_PORT    = 1119

# Service IDs (from HearthSim / community docs)
SVC_CONNECTION = 0
SVC_AUTH       = 1
SVC_GAME_MASTER = 6

# Method IDs for Connection service (svc 0)
METHOD_CONNECT_RESPONSE = 1

# Method IDs for Auth service
METHOD_LOGON          = 1
METHOD_LOGON_COMPLETE = 10

# Method IDs for GameMaster service
METHOD_LIST_GAMES = 1


# ---------------------------------------------------------------------------
# BnetClient
# ---------------------------------------------------------------------------

class BnetClient:
    """
    Connects to Battle.net 2.0 on port 1119 and streams SC2 arcade lobby events.

    Usage:
        client = BnetClient(
            username="your@email.com",
            password="YourPassword",
            region="us",
        )
        client.on_signal = lambda line: print(line)
        client.connect()  # blocks, call from a thread

    The on_signal callback receives decoded journal signal lines
    (e.g. "LBCR:4\\x01...") which can be fed to signal_decoder.decode_line().

    -----------------------------------------------------------------------
    WHAT IS IMPLEMENTED HERE:
      - TLS connection + socket management
      - Frame reader / writer (2-byte length + protobuf header + body)
      - Connection service request (svc 0, method 1) — the "hello"
      - Skeleton auth methods (need SRP6 implementation to fully work)
      - GameMaster lobby list request

    WHAT NEEDS TO BE ADDED FOR FULL AUTH:
      - SRP6 challenge/response (Blizzard variant)
        Library: srptools (pip install srptools)
      - Actual Battle.net account credentials
      - Correct proto definitions for Logon + LogonChallenge messages
    -----------------------------------------------------------------------
    """

    def __init__(self, username: str, password: str, region: str = "us"):
        self.username = username
        self.password = password
        self.region   = region
        self.host     = f"{region}.actual.battle.net"

        self._sock:   Optional[ssl.SSLSocket] = None
        self._token   = 0
        self._running = False
        self._lock    = threading.Lock()

        # Callback: receives raw signal lines (str)
        self.on_signal: Optional[Callable[[str], None]] = None
        # Callback: connection state changes
        self.on_status: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open TLS connection, authenticate, and start streaming. Blocks."""
        ctx = ssl.create_default_context()
        # Blizzard uses valid CA certs — no need to disable verification
        raw = socket.create_connection((self.host, BNET_PORT), timeout=30)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        log.info(f"TLS connected to {self.host}:{BNET_PORT} "
                 f"({self._sock.version()})")
        self._running = True
        self._status("connected")

        try:
            self._handshake()
            self._auth()
            self._request_lobby_list()
            self._read_loop()
        except Exception as e:
            log.error(f"Connection error: {e}")
            self._status(f"error: {e}")
        finally:
            self._running = False
            if self._sock:
                self._sock.close()

    def disconnect(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()

    # ------------------------------------------------------------------
    # Internal protocol steps
    # ------------------------------------------------------------------

    def _next_token(self) -> int:
        self._token += 1
        return self._token

    def _send_frame(self, service_id: int, method_id: int,
                    body: bytes = b"", object_id: int = 0) -> int:
        tok  = self._next_token()
        data = _encode_frame(service_id, method_id, tok, body, object_id)
        with self._lock:
            self._sock.sendall(data)
        return tok

    def _recv_frame(self) -> tuple[dict, bytes]:
        """Read one complete frame. Returns (header_dict, body_bytes)."""
        raw_len = self._recv_exactly(2)
        hdr_len = struct.unpack(">H", raw_len)[0]
        hdr_bytes = self._recv_exactly(hdr_len)
        hdr = _decode_header(hdr_bytes)
        body_size = hdr.get(5, 0)
        body = self._recv_exactly(body_size) if body_size else b""
        return hdr, body

    def _recv_exactly(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Remote closed connection")
            buf += chunk
        return buf

    def _handshake(self) -> None:
        """
        Send the Battle.net 2.0 connection request (service 0, method 1).

        ConnectRequest body (simplified proto):
          message ConnectRequest {
            ClientId client_id = 1;
            BindRequest bind_request = 2;
          }
          message BindRequest {
            repeated ImportedService imported_service = 1;
          }

        For SC2 lobby access we import the GameMaster service.
        We send a minimal body and let the server respond with ConnectResponse.
        """
        log.info("Sending connection handshake...")
        # Minimal ConnectRequest — empty body triggers server challenge
        self._send_frame(SVC_CONNECTION, METHOD_CONNECT_RESPONSE, b"")
        hdr, body = self._recv_frame()
        log.debug(f"ConnectResponse header: {hdr}")
        self._status("handshake_ok")

    def _auth(self) -> None:
        """
        Authentication via SRP6 challenge/response.

        This is the part that requires real credentials AND the SRP6
        implementation.  The protocol:

          1. Client → Server: Logon(email, program="S2  ", platform="Mac",
                                    locale="enUS", version=...)
          2. Server → Client: LogonChallenge(srp_b, srp_salt)
          3. Client → Server: LogonProof(srp_a, srp_m1, proof)
          4. Server → Client: LogonProofResponse(srp_m2)  → authenticated

        To complete this:
          pip install srptools
          See: https://github.com/nicowillis/srptools

        TODO: Implement SRP6 exchange here.
        """
        log.warning(
            "AUTH STUB — real Battle.net credentials + SRP6 are required.\n"
            "  This method needs to be completed with the full SRP6 flow.\n"
            "  See the docstring for the exchange sequence."
        )
        self._status("auth_stub")
        raise NotImplementedError(
            "SRP6 authentication not yet implemented. "
            "Provide a real Battle.net account and implement the SRP6 exchange."
        )

    def _request_lobby_list(self) -> None:
        """
        Call GameMasterService.ListAvailableGames (svc 6, method 1).

        Request body fields (inferred from sc2-arcade-watcher + community docs):
          message ListAvailableGamesRequest {
            uint32 game_type   = 1;   // 5 = arcade
            uint32 region      = 2;   // 1 = US
            uint32 max_results = 3;
          }
        """
        body = (
            _proto_field(1, 0, 5) +   # game_type = arcade
            _proto_field(2, 0, 1) +   # region = US
            _proto_field(3, 0, 500)   # max_results
        )
        self._send_frame(SVC_GAME_MASTER, METHOD_LIST_GAMES, body)
        log.info("Sent GameMaster.ListAvailableGames request")

    def _read_loop(self) -> None:
        """
        Continuously read frames from the server.
        Lobby list responses arrive as GameMasterNotify messages.
        When the on_signal callback is set, translate each lobby entry to
        a LBCR-format signal string and dispatch it.
        """
        log.info("Entering read loop...")
        while self._running:
            try:
                hdr, body = self._recv_frame()
                self._dispatch(hdr, body)
            except (ConnectionError, ssl.SSLError) as e:
                log.error(f"Read loop error: {e}")
                break

    def _dispatch(self, hdr: dict, body: bytes) -> None:
        """Handle a received frame. Override or extend this."""
        service_id = hdr.get(1, 0)
        method_id  = hdr.get(2, 0)
        log.debug(f"Frame svc={service_id} method={method_id} body={len(body)}B")

        if service_id == SVC_GAME_MASTER:
            self._handle_game_master(method_id, body)

    def _handle_game_master(self, method_id: int, body: bytes) -> None:
        """
        Parse a GameMaster response and emit signals.

        The response body is a ListAvailableGamesResponse protobuf.
        Each game entry contains: lobby_id, map_handle, lobby_name, host_name,
        slot counts, etc.

        Because we don't have the exact proto definition compiled, we'd need
        to parse the raw protobuf bytes.  Below is the stub — replace the
        TODO block with actual protobuf parsing once the .proto file is
        available or compiled with protoc.
        """
        # TODO: Parse body as ListAvailableGamesResponse
        # For each game in response.games:
        #   signal_line = f"LBCR:4\x01{timestamp}\x01{lobby.id}\x01{map_handle}\x01..."
        #   if self.on_signal:
        #       self.on_signal(signal_line)
        log.debug(f"GameMaster response: {len(body)} bytes (unparsed)")

    def _status(self, msg: str) -> None:
        log.info(f"Status: {msg}")
        if self.on_status:
            self.on_status(msg)


# ---------------------------------------------------------------------------
# Reconnecting wrapper
# ---------------------------------------------------------------------------

class ReconnectingBnetClient:
    """
    Wraps BnetClient with automatic reconnection and exponential backoff.
    """

    def __init__(self, username: str, password: str, region: str = "us",
                 max_backoff: float = 300.0):
        self.username    = username
        self.password    = password
        self.region      = region
        self.max_backoff = max_backoff
        self.on_signal:  Optional[Callable[[str], None]] = None
        self.on_status:  Optional[Callable[[str], None]] = None
        self._running    = False

    def start(self) -> None:
        """Start in the current thread with reconnection loop."""
        self._running = True
        backoff = 5.0
        while self._running:
            client = BnetClient(self.username, self.password, self.region)
            client.on_signal = self.on_signal
            client.on_status = self.on_status
            try:
                client.connect()
            except NotImplementedError:
                # Auth not implemented — don't retry
                log.error("Auth not implemented — stopping reconnect loop.")
                break
            except Exception as e:
                log.warning(f"Connection failed: {e}. Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff = min(backoff * 2, self.max_backoff)
                continue
            # Clean exit — reset backoff
            backoff = 5.0

    def stop(self) -> None:
        self._running = False
