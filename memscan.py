#!/usr/bin/env python3
"""
SC2 Memory Scanner
==================
Reads SC2's process memory directly via /proc/PID/mem to find lobby names.
No injection, no Frida — reads memory regions mapped as readable.

Usage:
    sudo python3 memscan.py <PID>
    sudo python3 memscan.py <PID> --watch   # re-scan every 5s
    sudo python3 memscan.py <PID> --term "Desert Strike"  # search specific term
"""
import os, sys, re, struct, time, argparse

# Known SC2 arcade game names to anchor our search
KNOWN_NAMES = [
    "Desert Strike", "Nexus Wars", "Phantom Mode", "Left 2 Die",
    "Squadron Tower Defense", "Diplomacy", "Starjeweled", "Aiur Chef",
    "Zealot Hockey", "Mini-Games", "Marine Arena", "Bunker Wars",
    "Cat and Mouse", "Micro Tournament", "Direct Strike", "Monobattle",
]


def get_readable_maps(pid: int) -> list[tuple[int, int, str]]:
    """Parse /proc/PID/maps and return readable regions (start, end, perms)."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                addr_range = parts[0]
                perms = parts[1] if len(parts) > 1 else ""
                name = parts[-1] if len(parts) > 5 else ""

                # Only readable regions, skip special files
                if "r" not in perms:
                    continue
                if any(x in name for x in ("[vvar]", "[vsyscall]")):
                    continue

                start_s, end_s = addr_range.split("-")
                start, end = int(start_s, 16), int(end_s, 16)
                size = end - start

                # Skip huge regions (> 512MB) — likely GPU/video memory
                if size > 512 * 1024 * 1024:
                    continue

                regions.append((start, end, name))
    except PermissionError:
        print(f"[!] Permission denied reading /proc/{pid}/maps — run with sudo")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] PID {pid} not found")
        sys.exit(1)
    return regions


def scan_region(mem_fd, start: int, end: int, patterns: list[bytes]) -> list[tuple[int, bytes, bytes]]:
    """Scan one memory region for patterns. Returns (offset, pattern, context)."""
    hits = []
    size = end - start
    try:
        os.lseek(mem_fd, start, os.SEEK_SET)
        data = os.read(mem_fd, size)
    except (OSError, OverflowError):
        return hits

    for pat in patterns:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx == -1:
                break
            context_start = max(0, idx - 64)
            context_end   = min(len(data), idx + len(pat) + 128)
            context = data[context_start:context_end]
            hits.append((start + idx, pat, context))
            pos = idx + 1

    return hits


def extract_strings_near(data: bytes, min_len: int = 4) -> list[str]:
    """Pull printable strings from a bytes blob."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def scan_pid(pid: int, search_terms: list[str]) -> dict[str, list[dict]]:
    """Full memory scan for search_terms. Returns {term: [hits]}."""
    results: dict[str, list[dict]] = {t: [] for t in search_terms}

    regions = get_readable_maps(pid)
    print(f"[+] {len(regions)} readable memory regions to scan")

    try:
        mem_fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except PermissionError:
        print(f"[!] Cannot open /proc/{pid}/mem — run with sudo")
        sys.exit(1)

    patterns = {t: t.encode("utf-8") for t in search_terms}
    # Also try UTF-16LE (Windows wide strings common in Wine)
    patterns_wide = {t: t.encode("utf-16-le") for t in search_terms}

    total_scanned = 0
    for start, end, name in regions:
        size = end - start
        total_scanned += size

        for term, pat in patterns.items():
            hits = scan_region(mem_fd, start, end, [pat, patterns_wide[term]])
            for addr, matched_pat, context in hits:
                encoding = "utf8" if matched_pat == pat else "utf16le"
                nearby = extract_strings_near(context, min_len=4)
                results[term].append({
                    "addr":     hex(addr),
                    "region":   name,
                    "encoding": encoding,
                    "context":  nearby,
                })

    os.close(mem_fd)
    print(f"[+] Scanned {total_scanned / 1024 / 1024:.0f} MB across {len(regions)} regions")
    return results


def main():
    parser = argparse.ArgumentParser(description="SC2 memory scanner")
    parser.add_argument("pid",  type=int, help="SC2 process PID")
    parser.add_argument("--watch", action="store_true", help="Rescan every 5s")
    parser.add_argument("--term", action="append", dest="terms",
                        help="Additional search terms (repeatable)")
    args = parser.parse_args()

    search_terms = list(KNOWN_NAMES)
    if args.terms:
        search_terms += args.terms

    print(f"[+] SC2 Memory Scanner — PID {args.pid}")
    print(f"[+] Searching for {len(search_terms)} terms")
    print()

    while True:
        results = scan_pid(args.pid, search_terms)

        found_any = False
        for term, hits in results.items():
            if hits:
                found_any = True
                print(f"\n[FOUND] '{term}' — {len(hits)} location(s):")
                for h in hits[:3]:  # show first 3 hits per term
                    print(f"  addr={h['addr']}  region={h['region']}  enc={h['encoding']}")
                    interesting = [s for s in h['context'] if len(s) > 5][:8]
                    for s in interesting:
                        print(f"    near: {s!r}")

        if not found_any:
            print("[~] No known lobby names found in memory yet.")
            print("    Make sure SC2 is on the arcade browser screen with lobbies visible.")

        if not args.watch:
            break

        print(f"\n[~] Rescanning in 5s...  ({time.strftime('%H:%M:%S')})")
        time.sleep(5)


if __name__ == "__main__":
    main()
