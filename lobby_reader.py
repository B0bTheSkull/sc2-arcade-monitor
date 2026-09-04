#!/usr/bin/env python3
"""
SC2 Arcade Lobby Reader
=======================
Reads live SC2 arcade lobby data directly from SC2's process memory via /proc/PID/mem.
No injection required — only standard Linux process memory reading (needs sudo or ptrace cap).

Memory layout discovered by manual analysis of SC2's heap:
  Each lobby entry contains:
    [len:1][lobby_name:len]  [binary metadata]  s2mh\x00\x00[region:2][hash:32]
    [binary data]  \x00\x01\x00\x29\x99\x00\x00\x00\x00[tag_len:1][battletag+data]

Lobby names are length-prefixed (1 byte, immediately before the string).
Region is 2 ASCII bytes 6 bytes after the 's2mh' marker.
BattleTags follow the 9-byte constant prefix \x00\x01\x00\x29\x99\x00\x00\x00\x00.

Usage:
    sudo python3 lobby_reader.py <PID>
    sudo python3 lobby_reader.py <PID> --watch        # rescan every 5s
    sudo python3 lobby_reader.py <PID> --json         # output JSON
    sudo python3 lobby_reader.py --find               # auto-find SC2 PID
"""
import os, sys, re, struct, time, json, argparse

# ── constants ─────────────────────────────────────────────────────────────────

S2MH_MARKER   = b"s2mh"
PLAYER_PREFIX = b"\x00\x01\x00\x29\x99\x00\x00\x00\x00"

# Scan regions >512MB are skipped (GPU/video memory); adjust as needed
MAX_REGION_SIZE = 512 * 1024 * 1024

# Max bytes to look back from s2mh for the lobby name
LOOKBACK = 128

# Max bytes to scan after s2mh for player entries
LOOKAHEAD = 512


# ── process memory helpers ────────────────────────────────────────────────────

def find_sc2_pid() -> int | None:
    """Walk /proc looking for SC2.exe or SC2_x64.exe."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                comm = f.read().strip()
            if comm.lower() in ("sc2.exe", "sc2_x64.exe", "sc2"):
                return int(entry)
            # also check cmdline for StarCraft II
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").lower()
            if "sc2" in cmdline or "starcraft ii" in cmdline:
                return int(entry)
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return None


def get_readable_maps(pid: int) -> list[tuple[int, int, str]]:
    """Return list of (start, end, name) for readable memory regions."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                perms = parts[1] if len(parts) > 1 else ""
                name  = parts[-1] if len(parts) > 5 else ""
                if "r" not in perms:
                    continue
                if any(x in name for x in ("[vvar]", "[vsyscall]")):
                    continue
                start_s, end_s = parts[0].split("-")
                start, end = int(start_s, 16), int(end_s, 16)
                if end - start > MAX_REGION_SIZE:
                    continue
                regions.append((start, end, name))
    except PermissionError:
        print(f"[!] Permission denied reading /proc/{pid}/maps — run with sudo", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] PID {pid} not found", file=sys.stderr)
        sys.exit(1)
    return regions


def read_region(mem_fd: int, start: int, size: int) -> bytes | None:
    """Read up to `size` bytes from the given address."""
    try:
        os.lseek(mem_fd, start, os.SEEK_SET)
        return os.read(mem_fd, size)
    except (OSError, OverflowError):
        return None


# ── lobby name extraction ─────────────────────────────────────────────────────

def extract_lobby_name(buf: bytes, s2mh_offset: int) -> str | None:
    """
    Given the buffer and the offset of the 's2mh' marker within it,
    search backwards for a length-prefixed ASCII string.
    Returns the lobby name or None.
    """
    lo = max(0, s2mh_offset - LOOKBACK)
    window = buf[lo:s2mh_offset]

    # Walk backwards looking for a valid length-prefixed printable string.
    # The byte at position i is the length, and window[i+1:i+1+length] is the name.
    best = None
    for i in range(len(window) - 1, -1, -1):
        length = window[i]
        if length < 3 or length > 80:
            continue
        end = i + 1 + length
        if end > len(window):
            continue
        candidate = window[i + 1:end]
        # Must be all printable ASCII
        if all(32 <= b < 127 for b in candidate):
            # Prefer the longest match closest to s2mh
            name = candidate.decode("ascii")
            if best is None:
                best = name
                break  # take first (closest) valid match walking backwards
    return best


# ── player name extraction ────────────────────────────────────────────────────

BATTLETAG_RE = re.compile(rb"([A-Za-z][A-Za-z0-9\-]{2,11})#(\d{1,6})")


def extract_players(buf: bytes, after_offset: int) -> list[str]:
    """
    Scan `buf[after_offset : after_offset+LOOKAHEAD]` for player BattleTags.
    Uses both the 9-byte constant prefix and a regex fallback.
    Returns list of 'Name#NNNN' strings.
    """
    window = buf[after_offset:after_offset + LOOKAHEAD]
    players: list[str] = []
    seen: set[str] = set()

    # Method 1: 9-byte constant prefix → next byte is tag_len, then string
    pos = 0
    while True:
        idx = window.find(PLAYER_PREFIX, pos)
        if idx == -1:
            break
        name_start = idx + len(PLAYER_PREFIX) + 1  # skip prefix + 1 length byte
        if name_start >= len(window):
            break
        # The length byte right after prefix covers name + binary suffix;
        # use regex to extract the printable BattleTag portion
        chunk = window[name_start:name_start + 64]
        m = BATTLETAG_RE.search(chunk)
        if m:
            tag = f"{m.group(1).decode()}\u200b#{m.group(2).decode()}"
            tag = m.group(1).decode() + "#" + m.group(2).decode()
            if tag not in seen:
                seen.add(tag)
                players.append(tag)
        pos = idx + 1

    # Method 2: BattleTag regex across the whole window (catches any missed)
    for m in BATTLETAG_RE.finditer(window):
        tag = m.group(1).decode() + "#" + m.group(2).decode()
        if tag not in seen:
            seen.add(tag)
            players.append(tag)

    return players


# ── player count extraction ───────────────────────────────────────────────────

def extract_player_count(buf: bytes, s2mh_offset: int) -> int | None:
    """
    The byte immediately before s2mh (or 1-3 bytes before) encodes
    the current player count in the lobby. Heuristic: find the last
    small integer (1-16) in the 3 bytes preceding s2mh.
    """
    if s2mh_offset < 3:
        return None
    for offset in range(1, 4):
        val = buf[s2mh_offset - offset]
        if 1 <= val <= 16:
            return val
    return None


# ── main scanner ──────────────────────────────────────────────────────────────

def scan_lobbies(pid: int) -> list[dict]:
    """
    Full memory scan. Returns list of lobby dicts:
      {name, region, players, player_count, addr}
    """
    regions = get_readable_maps(pid)

    try:
        mem_fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except PermissionError:
        print(f"[!] Cannot open /proc/{pid}/mem — run with sudo", file=sys.stderr)
        sys.exit(1)

    lobbies: list[dict] = []
    seen_names: set[str] = set()

    for start, end, _name in regions:
        size = end - start
        data = read_region(mem_fd, start, size)
        if data is None:
            continue

        # Find all s2mh markers in this region
        pos = 0
        while True:
            idx = data.find(S2MH_MARKER, pos)
            if idx == -1:
                break

            abs_addr = start + idx

            # Extract region code: s2mh + 00 00 + [2 chars]
            region = ""
            if idx + 8 <= len(data):
                region_bytes = data[idx + 6:idx + 8]
                if all(32 <= b < 127 for b in region_bytes):
                    region = region_bytes.decode("ascii")

            # Extract lobby name from before s2mh
            lobby_name = extract_lobby_name(data, idx)

            # Extract player count from bytes just before s2mh
            player_count = extract_player_count(data, idx)

            # Extract player BattleTags from after s2mh (skip 40-byte s2mh block)
            after = idx + 4 + 2 + 2 + 32  # s2mh + 00 00 + region + hash
            players = extract_players(data, after)

            if lobby_name and region:
                key = f"{lobby_name}|{region}"
                if key not in seen_names:
                    seen_names.add(key)
                    lobbies.append({
                        "name":         lobby_name,
                        "region":       region,
                        "player_count": player_count,
                        "players":      players,
                        "addr":         hex(abs_addr),
                    })

            pos = idx + 1

    os.close(mem_fd)
    return lobbies


# ── output formatting ─────────────────────────────────────────────────────────

def print_lobbies(lobbies: list[dict]) -> None:
    if not lobbies:
        print("[~] No lobbies found — make sure SC2 is showing the Arcade browser.")
        return

    print(f"[+] {len(lobbies)} lobby/lobbies found:\n")
    for i, lb in enumerate(lobbies, 1):
        pc   = lb["player_count"]
        pc_s = f"{pc} player(s)" if pc else "? players"
        print(f"  {i:2}. [{lb['region']}] {lb['name']}  ({pc_s})")
        for p in lb["players"]:
            print(f"        • {p}")
    print()


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SC2 arcade lobby reader (memory-based)")
    parser.add_argument("pid",    type=int, nargs="?", help="SC2 process PID")
    parser.add_argument("--find", action="store_true",  help="Auto-detect SC2 PID")
    parser.add_argument("--watch", action="store_true", help="Re-scan every 5s")
    parser.add_argument("--json", action="store_true",  help="Output JSON instead of human-readable")
    args = parser.parse_args()

    if args.find or args.pid is None:
        pid = find_sc2_pid()
        if pid is None:
            print("[!] Could not auto-detect SC2 process. Pass PID explicitly.", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Found SC2 PID: {pid}")
    else:
        pid = args.pid

    print(f"[+] SC2 Lobby Reader — PID {pid}")
    print()

    while True:
        lobbies = scan_lobbies(pid)

        if args.json:
            print(json.dumps(lobbies, indent=2))
        else:
            print(f"[{time.strftime('%H:%M:%S')}]", end="  ")
            print_lobbies(lobbies)

        if not args.watch:
            break

        time.sleep(5)


if __name__ == "__main__":
    main()
