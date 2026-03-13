# SC2 Arcade Lobby Monitor

Monitors the local SC2 client cache to surface arcade lobby names in a live web UI — no Battle.net authentication required.

## How it works

When SC2 browses the Custom Games / Arcade lobby list it downloads `.s2ml` (map locale) files to:
```
/Users/Shared/Blizzard/Battle.net/Cache/{hash[0:2]}/{hash[2:4]}/{hash}.s2ml
```

These XML files contain the human-readable game name and description for each lobby.
The monitor scans these files by modification time and serves them over a local REST API.

**Freshness tiers:**
| Badge | Meaning |
|---|---|
| 🟢 Live | Downloaded in last 10 min — confirmed in current lobby list |
| 🔵 Today | Downloaded today |
| 🟣 This week | Seen this week |
| Cached | Older entry — game exists but current activity unknown |

> **Limitation:** APFS does not update access times on reads. Games already in SC2's local cache will not get a fresh timestamp until their map file is updated and re-downloaded. The auto-scroller helps by triggering new downloads as SC2 scrolls through the lobby list.

---

## Files

| File | Description |
|---|---|
| `sc2_cache_monitor.py` | REST API server — scans cache, serves `/lobbies/active` |
| `sc2_arcade_scroller.py` | Sends Page Down/Up keystrokes to SC2 to trigger new downloads |
| `sc2_arcade.html` | Web UI — open in any browser |
| `sc2_arcade/` | Original sc2_arcade package (api_server, lobby_tracker, bnet_client stubs) |

---

## Quick start

```bash
# 1. Start the monitor (keep running in background)
python3 sc2_cache_monitor.py

# 2. (Optional) Start the auto-scroller to keep data fresh
python3 sc2_arcade_scroller.py

# 3. Open the UI
open sc2_arcade.html
```

The auto-scroller requires **Accessibility permission** for Terminal:
`System Settings → Privacy & Security → Accessibility → add Terminal`

---

## API

```
GET http://localhost:8080/lobbies/active           # all cached games
GET http://localhost:8080/lobbies/active?region=english
GET http://localhost:8080/lobbies/active?region=korean
GET http://localhost:8080/lobbies/active?stale=600  # only last 10 min
GET http://localhost:8080/stats
GET http://localhost:8080/health
```

**Region values:** `english` · `korean` · `russian` · `chinese` · `european` · `other`

---

## Auto-start (macOS launchd)

```bash
cat > ~/Library/LaunchAgents/com.sc2arcade.monitor.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.sc2arcade.monitor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/path/to/sc2_cache_monitor.py</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/sc2arcade.log</string>
  <key>StandardErrorPath</key><string>/tmp/sc2arcade.log</string>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.sc2arcade.monitor.plist
```

---

## Platform notes

- **macOS only** — uses APFS cache directory and macOS AppleScript for the scroller
- SC2 cache path: `/Users/Shared/Blizzard/Battle.net/Cache/`
- Python 3.10+ required (uses `str | None` union syntax)
