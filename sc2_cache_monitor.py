#!/usr/bin/env python3
"""
SC2 Arcade Lobby Monitor - Cache Scanner (optimized)
=====================================================
Scans /Users/Shared/Blizzard/Battle.net/Cache for recently downloaded .s2ml
files (SC2 arcade lobby map locale descriptors).  Deduplicates across locale
variants so each unique game appears once, with all its known locales tracked.

REST API at http://localhost:8080/lobbies/active
"""
import os, sys, time, json, threading, subprocess, xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── config ────────────────────────────────────────────────────────────────────
CACHE_DIR      = "/home/kali/Games/battlenet/drive_c/ProgramData/Blizzard Entertainment/Battle.net/Cache"
API_PORT       = 8080
POLL_INTERVAL  = 3        # seconds between cache scans
ACTIVE_WINDOW  = 0        # 0 = no time limit, show full cache

# Locale preference order for display names (first match wins)
LOCALE_PREF = ["enUS", "enGB", "deDE", "frFR", "esES", "esMX", "ptBR",
               "plPL", "itIT", "ruRU", "zhCN", "zhTW", "koKR"]

# Locale → region grouping for the frontend filter
LOCALE_REGION = {
    "enUS": "english", "enGB": "english",
    "koKR": "korean",
    "ruRU": "russian",
    "zhCN": "chinese", "zhTW": "chinese",
    "deDE": "european", "frFR": "european", "plPL": "european",
    "itIT": "european", "esES": "european", "esMX": "european",
    "ptBR": "european",
}

# ── shared state ──────────────────────────────────────────────────────────────
# Keyed by normalized game name (lowercase strip).
# Each value: {name, description, best_locale, locales: list, regions: list,
#              last_seen, first_seen}
lobbies: dict[str, dict] = {}
lock = threading.Lock()
stats = {"scans": 0, "last_scan": 0.0}


# ── parser ────────────────────────────────────────────────────────────────────

def parse_s2ml(path: str) -> dict | None:
    try:
        raw = open(path, "rb").read()
        root = ET.fromstring(raw.decode("utf-8", errors="replace"))
        locale = root.attrib.get("region", "")
        fields: dict[str, str] = {}
        for elem in root:
            fid = elem.attrib.get("id")
            if fid and elem.text:
                fields[fid] = elem.text.strip()
        name = fields.get("1", "").strip()
        desc = fields.get("2", "").strip()
        if not name:
            return None
        return {"name": name, "description": desc, "locale": locale}
    except Exception:
        return None


def locale_rank(locale: str) -> int:
    try:
        return LOCALE_PREF.index(locale)
    except ValueError:
        return len(LOCALE_PREF)


# ── cache scanner ─────────────────────────────────────────────────────────────

def scan_cache() -> int:
    now = time.time()
    new_games = 0

    for top in os.scandir(CACHE_DIR):
        if not top.is_dir():
            continue
        for mid in os.scandir(top.path):
            if not mid.is_dir():
                continue
            for entry in os.scandir(mid.path):
                if not entry.is_file() or not entry.name.endswith(".s2ml"):
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    continue

                if ACTIVE_WINDOW and now - mtime > ACTIVE_WINDOW:
                    continue

                parsed = parse_s2ml(entry.path)
                if not parsed:
                    continue

                name     = parsed["name"]
                locale   = parsed["locale"]
                desc     = parsed["description"]
                norm_key = name.lower().strip()
                region   = LOCALE_REGION.get(locale, "other")

                with lock:
                    existing = lobbies.get(norm_key)
                    if existing is None:
                        # New game
                        lobbies[norm_key] = {
                            "name":        name,
                            "description": desc,
                            "best_locale": locale,
                            "locales":     [locale] if locale else [],
                            "regions":     [region],
                            "last_seen":   mtime,
                            "first_seen":  mtime,
                        }
                        new_games += 1
                    else:
                        # Known game — update locale list and best name
                        if locale and locale not in existing["locales"]:
                            existing["locales"].append(locale)
                        if region not in existing["regions"]:
                            existing["regions"].append(region)

                        # Upgrade to a better locale if possible
                        if locale_rank(locale) < locale_rank(existing["best_locale"]):
                            existing["best_locale"] = locale
                            existing["name"]        = name
                            existing["description"] = desc

                        if mtime > existing["last_seen"]:
                            existing["last_seen"] = mtime

    with lock:
        stats["scans"] += 1
        stats["last_scan"] = now

    return new_games


def notify(title: str, body: str):
    try:
        subprocess.run(["notify-send", "-a", "SC2 Arcade Monitor", title, body],
                       check=False, capture_output=True)
    except FileNotFoundError:
        pass  # notify-send not installed


def scanner_loop():
    while True:
        try:
            n = scan_cache()
            if n > 0:
                with lock:
                    total = len(lobbies)
                print(f"[cache] +{n} new games  total={total}")
                notify(f"+{n} new arcade game{'s' if n != 1 else ''}",
                       f"{total} total games in cache")
        except Exception as e:
            print(f"[cache] scan error: {e}")
        time.sleep(POLL_INTERVAL)


# ── REST API ──────────────────────────────────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs     = parse_qs(parsed.query)
        path   = parsed.path.rstrip("/")

        if path in ("/lobbies/active", "/lobbies", "/lobbies/recent"):
            self._handle_lobbies(qs)
        elif path == "/health":
            self._json({"status": "ok", "api_port": API_PORT,
                        "cache_dir": CACHE_DIR, "poll_interval": POLL_INTERVAL})
        elif path == "/stats":
            with lock:
                now    = time.time()
                total  = len(lobbies)
                active = sum(1 for v in lobbies.values()
                             if now - v["last_seen"] < ACTIVE_WINDOW)
                fresh  = sum(1 for v in lobbies.values()
                             if now - v["last_seen"] < 300)
            self._json({
                "total_games":       total,
                "active_1h":         active,
                "fresh_5min":        fresh,
                "scans_completed":   stats["scans"],
                "last_scan_ago_s":   round(time.time() - stats["last_scan"], 1),
                "active_window_s":   ACTIVE_WINDOW,
                "poll_interval_s":   POLL_INTERVAL,
            })
        else:
            self._json({"error": "not found",
                        "endpoints": ["/lobbies/active", "/stats", "/health"]}, 404)

    def _handle_lobbies(self, qs: dict):
        stale  = float(qs.get("stale",  [str(ACTIVE_WINDOW)])[0])
        limit  = int(  qs.get("limit",  ["500"])[0])
        region = qs.get("region", [None])[0]   # filter: english/korean/russian/chinese/european/other
        now    = time.time()

        with lock:
            entries = [
                v for v in lobbies.values()
                if not stale or now - v["last_seen"] < stale
            ]

        if region:
            region = region.lower()
            entries = [e for e in entries if region in e["regions"]]

        entries.sort(key=lambda x: -x["last_seen"])

        result = []
        for e in entries[:limit]:
            age = now - e["last_seen"]
            if age < 600:       freshness = "live"      # <10 min
            elif age < 86400:   freshness = "today"     # <24 h
            elif age < 604800:  freshness = "week"      # <7 days
            else:               freshness = "cached"    # older
            result.append({
                "name":            e["name"],
                "description":     e["description"],
                "best_locale":     e["best_locale"],
                "locales":         sorted(e["locales"]),
                "regions":         sorted(e["regions"]),
                "last_seen":       e["last_seen"],
                "last_seen_ago_s": round(age, 1),
                "freshness":       freshness,
            })

        # Aggregate region counts for the filter bar
        region_counts: dict[str, int] = {}
        with lock:
            for e in lobbies.values():
                if stale and now - e["last_seen"] >= stale:
                    continue
                for r in e["regions"]:
                    region_counts[r] = region_counts.get(r, 0) + 1

        self._json({
            "count":         len(result),
            "source":        "sc2_cache_monitor",
            "window_s":      stale,
            "region_filter": region,
            "region_counts": region_counts,
            "lobbies":       result,
        })

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


# ── main ──────────────────────────────────────────────────────────────────────

def kill_port(port: int):
    for pid in subprocess.run(["lsof", "-t", f"-i:{port}"],
                              capture_output=True, text=True).stdout.split():
        try:
            os.kill(int(pid.strip()), 15)
            time.sleep(0.4)
        except Exception:
            pass


def main():
    import signal as sig

    print(f"[+] SC2 Arcade Cache Monitor")
    print(f"[+] Cache  : {CACHE_DIR}")
    print(f"[+] API    : http://localhost:{API_PORT}/lobbies/active")
    print(f"[+] Window : {ACTIVE_WINDOW}s  |  Poll: {POLL_INTERVAL}s")
    print()

    kill_port(API_PORT)

    print("[*] Initial scan...", end="", flush=True)
    scan_cache()
    with lock:
        print(f" {len(lobbies)} games loaded.")
    print()

    threading.Thread(target=scanner_loop, daemon=True).start()

    server = HTTPServer(("0.0.0.0", API_PORT), APIHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"[+] Listening on http://localhost:{API_PORT}")
    print(f"    /lobbies/active           — all games this hour")
    print(f"    /lobbies/active?region=english")
    print(f"    /lobbies/active?region=korean")
    print(f"    /lobbies/active?stale=300 — only last 5 min")
    print(f"    /stats  /health")
    print()
    print("[!] Ctrl+C to stop.")

    def _stop(s, f):
        print("\n[!] Stopping...")
        server.shutdown()
        sys.exit(0)

    sig.signal(sig.SIGINT, _stop)
    sig.signal(sig.SIGTERM, _stop)

    last = -1
    while True:
        time.sleep(5)
        with lock:
            n = len(lobbies)
        if n != last:
            print(f"[status] {n} unique games tracked")
            last = n


if __name__ == "__main__":
    main()
