# SC2 Arcade Lobby Monitor

Monitors the local SC2 client cache to surface arcade lobby names in a live web UI — no Battle.net authentication required.

## How it works

When SC2 browses the Custom Games / Arcade lobby list it downloads `.s2ml` (map locale) files to a local cache directory. These XML files contain the human-readable game name and description for each lobby. The monitor scans these files by modification time and serves them over a local REST API.

The auto-refresher periodically clicks the in-game refresh button via `xdotool`, triggering new `.s2ml` downloads without you touching the game.

**Freshness tiers:**
| Badge | Meaning |
|---|---|
| 🟢 Live | Downloaded in last 10 min |
| 🔵 Today | Downloaded today |
| 🟣 This week | Seen this week |
| Cached | Older — game exists but current activity unknown |

---

## Requirements

- Linux with SC2 running via Lutris / Wine
- Python 3.10+
- `xdotool` — `sudo apt install xdotool`
- `libnotify-bin` (optional, for desktop notifications) — `sudo apt install libnotify-bin`

---

## Setup

**1. Set the cache path** in `sc2_cache_monitor.py`:
```python
CACHE_DIR = "/home/kali/Games/battlenet/drive_c/ProgramData/Blizzard Entertainment/Battle.net/Cache"
```
Adjust to match your Wine prefix if different.

**2. Calibrate the refresh button** (one time):
```bash
python3 sc2_arcade_scroller.py --calibrate
```
Switch to SC2, hover over the refresh button in the arcade browser, press Enter. Saves to `.refresh_coords.json`.

---

## Running

```bash
# Terminal 1 — cache monitor + REST API
python3 sc2_cache_monitor.py

# Terminal 2 — auto-refresher
python3 sc2_arcade_scroller.py

# Open the UI
xdg-open sc2_arcade.html
```

---

## API

```
GET http://localhost:8080/lobbies/active
GET http://localhost:8080/lobbies/active?region=english
GET http://localhost:8080/lobbies/active?region=korean
GET http://localhost:8080/lobbies/active?stale=600
GET http://localhost:8080/stats
GET http://localhost:8080/health
```

**Region values:** `english` · `korean` · `russian` · `chinese` · `european` · `other`
