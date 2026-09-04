#!/usr/bin/env bash
# Capture decrypted Battle.net traffic from SC2 (port 1119)
#
# Usage:
#   ./capture.sh           # start capture, Ctrl+C to stop
#   ./capture.sh --decode  # decode latest pcap after capture
#
# Requires: tcpdump (sudo apt install tcpdump)
# SSLKEYLOGFILE is injected via the Lutris game config automatically.
# Launch SC2 via Lutris AFTER starting this script, then browse the arcade.

set -e

CAPTURE_DIR="$(dirname "$0")"
KEYLOG="$CAPTURE_DIR/keylog.txt"
PCAP="$CAPTURE_DIR/bnet_$(date +%Y%m%d_%H%M%S).pcapng"

if [[ "$1" == "--decode" ]]; then
    latest=$(ls -t "$CAPTURE_DIR"/*.pcapng 2>/dev/null | head -1)
    if [[ -z "$latest" ]]; then
        echo "[!] No pcap files found in $CAPTURE_DIR"
        exit 1
    fi
    echo "[+] Decoding: $latest"
    echo "[+] Keylog:   $KEYLOG"
    python3 "$(dirname "$0")/../bnet_decoder.py" "$latest" "$KEYLOG"
    exit 0
fi

echo "[+] SC2 Battle.net Capture"
echo "[+] Pcap:    $PCAP"
echo "[+] Keylog:  $KEYLOG"
echo "[+] Filter:  port 1119"
echo ""
echo "[*] Start SC2 via Lutris NOW, browse the Arcade lobby list."
echo "[!] Ctrl+C to stop capture."
echo ""

# Capture all traffic on port 1119 (Battle.net game protocol)
sudo tcpdump -i any -w "$PCAP" "port 1119"

echo ""
echo "[+] Capture saved to: $PCAP"
echo "[+] Run with --decode to extract lobby messages:"
echo "    ./capture.sh --decode"
