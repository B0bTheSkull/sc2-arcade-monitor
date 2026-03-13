"""
SC2 Arcade Lobby Tracker — Main Entry Point
============================================

Usage:
    # Replay signals from a journal file (test with existing data)
    python -m sc2_arcade journal --path /path/to/journal/dir

    # Read from pcap (parses what's visible — cleartext only)
    python -m sc2_arcade pcap --path ../scII.pcapng

    # Connect live to Battle.net (requires real BNet account + SRP6 auth)
    python -m sc2_arcade live --user you@email.com --pass YourPassword

    # Start just the REST API with dummy data
    python -m sc2_arcade serve

All modes start the REST API on http://localhost:8080
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time

from .signal_decoder import decode_line, decode_stream
from .lobby_tracker   import LobbyTracker
from .pcap_reader     import describe_pcap, extract_http_bodies, read_journal_file
from .api_server      import LobbyAPIServer
from .bnet_client     import ReconnectingBnetClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mode: journal
# ---------------------------------------------------------------------------

def run_journal(args, tracker: LobbyTracker) -> None:
    log.info(f"Reading journal from: {args.path}")
    lines = list(read_journal_file(args.path))
    log.info(f"Loaded {len(lines)} lines")
    signals = decode_stream(lines)
    tracker.process_many(signals)
    log.info(f"Tracker stats: {tracker.stats()}")


# ---------------------------------------------------------------------------
# Mode: pcap
# ---------------------------------------------------------------------------

def run_pcap(args, tracker: LobbyTracker) -> None:
    log.info(f"Analysing pcap: {args.path}")

    # Describe connections
    flows = describe_pcap(args.path)
    log.info("Top flows (src_port, dst_port) → packets:")
    for (sp, dp), count in list(flows.items())[:10]:
        log.info(f"  {sp:5d} → {dp:5d}  : {count} packets")

    # Extract any HTTP bodies (port 80 depot traffic)
    log.info("Extracting port-80 HTTP bodies...")
    for body in extract_http_bodies(args.path, target_port=80):
        text = body.decode("utf-8", errors="ignore")
        # Signal lines would appear here if they were in cleartext
        for line in text.splitlines():
            sig = decode_line(line)
            if sig:
                tracker.process(sig)
                log.info(f"  Signal: {sig}")

    log.info(
        "\nNOTE: Port 1119 (Battle.net) traffic is TLS-encrypted.\n"
        "      To decode it, capture SSLKEYLOGFILE from the SC2 process\n"
        "      and load it into Wireshark, then export decrypted traffic."
    )
    log.info(f"Tracker stats: {tracker.stats()}")


# ---------------------------------------------------------------------------
# Mode: live (Battle.net direct)
# ---------------------------------------------------------------------------

def run_live(args, tracker: LobbyTracker) -> None:
    log.info(f"Connecting to Battle.net as {args.user} (region: {args.region})")

    client = ReconnectingBnetClient(
        username=args.user,
        password=args.password,
        region=args.region,
    )

    def on_signal(line: str):
        sig = decode_line(line)
        if sig:
            tracker.process(sig)
            log.debug(f"Signal: {sig.kind.value} lobby={getattr(sig, 'lobby_id', '')}")

    def on_status(msg: str):
        log.info(f"BNet status: {msg}")

    client.on_signal = on_signal
    client.on_status = on_status

    t = threading.Thread(target=client.start, daemon=True, name="BNetClient")
    t.start()


# ---------------------------------------------------------------------------
# Mode: serve (API only, with synthetic demo data)
# ---------------------------------------------------------------------------

DEMO_JOURNAL = (
    # Synthetic signals to demonstrate the tracker when no real data exists
    "INIT:3\x011741000000\x01bucket-demo\x011-S2-1-1234567\r\n"
    "LBCR:4\x011741000001\x01lobby-001\x011-S2-1-99999\x01\x01\x010\x01Tower Defense Legends\x01PlayerOne\x012\x014\r\n"
    "LBCR:4\x011741000002\x01lobby-002\x011-S2-1-88888\x01\x01\x010\x01Desert Strike 2026\x01CoolDude\x013\x012\r\n"
    "LBCR:4\x011741000003\x01lobby-003\x011-S2-1-77777\x01\x01\x010\x01Mass Recall Custom\x01SCFan99\x010\x018\r\n"
    "LBPV:1\x011741000004\x012\x031\x030\x03PlayerOne\x01lobby-001\x010\x012\r\n"
    "LBPA:1\x011741000060\x01lobby-001\r\n"
    "LBPA:1\x011741000060\x01lobby-002\r\n"
    "LBPA:1\x011741000060\x01lobby-003\r\n"
)


def run_serve(args, tracker: LobbyTracker) -> None:
    log.info("Loading demo data...")
    lines = [l for l in DEMO_JOURNAL.split("\r\n") if l]
    signals = decode_stream(lines)
    tracker.process_many(signals)
    log.info(f"Demo tracker stats: {tracker.stats()}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SC2 Arcade Lobby Tracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-port", type=int, default=8080)
    parser.add_argument("--api-host", default="0.0.0.0")

    sub = parser.add_subparsers(dest="mode", required=True)

    p_journal = sub.add_parser("journal", help="Read journal file(s)")
    p_journal.add_argument("--path", required=True)

    p_pcap = sub.add_parser("pcap", help="Analyse pcap file")
    p_pcap.add_argument("--path", required=True)

    p_live = sub.add_parser("live", help="Connect live to Battle.net")
    p_live.add_argument("--user",     required=True, help="Battle.net email")
    p_live.add_argument("--password", required=True, help="Battle.net password")
    p_live.add_argument("--region",   default="us")

    sub.add_parser("serve", help="Start API with demo data")

    args = parser.parse_args()

    tracker = LobbyTracker()
    api     = LobbyAPIServer(tracker, host=args.api_host, port=args.api_port)
    api.start()

    if args.mode == "journal":
        run_journal(args, tracker)
    elif args.mode == "pcap":
        run_pcap(args, tracker)
    elif args.mode == "live":
        run_live(args, tracker)
    elif args.mode == "serve":
        run_serve(args, tracker)

    log.info(f"API running at http://{args.api_host}:{args.api_port}")
    log.info("Press Ctrl+C to quit")
    try:
        while True:
            time.sleep(5)
            stats = tracker.stats()
            log.info(f"Open lobbies: {stats['open']} | Total seen: {stats['created']}")
    except KeyboardInterrupt:
        log.info("Shutting down.")
        api.stop()


if __name__ == "__main__":
    main()
