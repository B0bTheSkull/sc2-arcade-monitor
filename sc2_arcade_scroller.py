#!/usr/bin/env python3
"""
SC2 Arcade Refresher (Linux / xdotool)
=======================================
Periodically clicks the arcade lobby refresh button in SC2 via xdotool.
Coordinates are stored relative to the SC2 window, so they survive window
moves. The real cursor is saved and restored around each click.

SC2 does NOT need to be the active/focused window.

Requirements:
  xdotool  (sudo apt install xdotool)

Usage:
  # One-time calibration — hover over the refresh button, press Enter:
  python3 sc2_arcade_scroller.py --calibrate

  # Run with saved or manually specified coordinates:
  python3 sc2_arcade_scroller.py
  python3 sc2_arcade_scroller.py --x 120 --y 38 --interval 30
"""
import subprocess, time, sys, argparse, os, json

WINDOW_NAME      = "StarCraft II"
DEFAULT_INTERVAL = 30
COORD_FILE       = os.path.join(os.path.dirname(__file__), ".refresh_coords.json")


def xdo(*args) -> str:
    r = subprocess.run(["xdotool", *args], capture_output=True, text=True)
    return r.stdout.strip()


def find_window() -> str | None:
    wids = xdo("search", "--name", WINDOW_NAME).splitlines()
    return wids[0] if wids else None


def get_window_geometry(wid: str) -> tuple[int, int]:
    """Return (x, y) top-left of window in screen coordinates."""
    out = xdo("getwindowgeometry", "--shell", wid)
    vals = dict(line.split("=") for line in out.splitlines() if "=" in line)
    return int(vals["X"]), int(vals["Y"])


def get_mouse() -> tuple[int, int]:
    out = xdo("getmouselocation", "--shell")
    vals = dict(line.split("=") for line in out.splitlines() if "=" in line)
    return int(vals["X"]), int(vals["Y"])


def click_in_window(wid: str, rel_x: int, rel_y: int):
    """Click at window-relative (rel_x, rel_y), restoring cursor afterwards."""
    wx, wy = get_window_geometry(wid)
    abs_x, abs_y = wx + rel_x, wy + rel_y

    saved = get_mouse()

    xdo("mousemove", "--sync", str(abs_x), str(abs_y))
    time.sleep(0.05)
    xdo("click", "1")
    time.sleep(0.05)

    xdo("mousemove", "--sync", str(saved[0]), str(saved[1]))


def save_coords(rel_x: int, rel_y: int):
    with open(COORD_FILE, "w") as f:
        json.dump({"rel_x": rel_x, "rel_y": rel_y}, f)


def load_coords() -> tuple[int, int] | None:
    if not os.path.exists(COORD_FILE):
        return None
    with open(COORD_FILE) as f:
        d = json.load(f)
    return d["rel_x"], d["rel_y"]


def calibrate():
    wid = find_window()
    if not wid:
        print(f"[!] SC2 window '{WINDOW_NAME}' not found. Is SC2 running?")
        sys.exit(1)

    print("[calibrate] Switch to SC2 and hover over the refresh button.")
    print("[calibrate] Press Enter to capture...")
    input()

    mx, my = get_mouse()
    wx, wy = get_window_geometry(wid)
    rel_x, rel_y = mx - wx, my - wy

    save_coords(rel_x, rel_y)
    print(f"[calibrate] Window origin: ({wx}, {wy})")
    print(f"[calibrate] Mouse position: ({mx}, {my})")
    print(f"[calibrate] Saved relative offset: ({rel_x}, {rel_y})")
    print(f"[calibrate] Done. Run without --calibrate to start.")


def main():
    parser = argparse.ArgumentParser(description="SC2 Arcade Auto-Refresher (Linux)")
    parser.add_argument("--calibrate", action="store_true",
                        help="Capture the refresh button position interactively")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help=f"Seconds between clicks (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--x", type=int, help="Refresh button X offset from window left edge")
    parser.add_argument("--y", type=int, help="Refresh button Y offset from window top edge")
    args = parser.parse_args()

    if args.calibrate:
        calibrate()
        return

    if args.x is not None and args.y is not None:
        rel_x, rel_y = args.x, args.y
    else:
        coords = load_coords()
        if not coords:
            print("[!] No coordinates saved. Run with --calibrate first.")
            sys.exit(1)
        rel_x, rel_y = coords

    wid = find_window()
    if not wid:
        print(f"[!] SC2 window '{WINDOW_NAME}' not found. Is SC2 running?")
        sys.exit(1)

    print(f"[+] SC2 Arcade Auto-Refresher")
    print(f"[+] Clicking at window offset ({rel_x}, {rel_y}) every {args.interval}s")
    print(f"[+] SC2 must be on the Custom Games / arcade browser screen")
    print(f"[!] Ctrl+C to stop")
    print()

    clicks = 0
    while True:
        wid = find_window()
        if not wid:
            print("[!] SC2 window lost. Waiting...")
            time.sleep(10)
            continue

        click_in_window(wid, rel_x, rel_y)
        clicks += 1
        print(f"[refresh] click #{clicks}  ({time.strftime('%H:%M:%S')})")

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
