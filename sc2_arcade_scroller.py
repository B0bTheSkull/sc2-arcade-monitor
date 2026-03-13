#!/usr/bin/env python3
"""
SC2 Arcade Auto-Scroller
========================
Periodically sends Page Down / Page Up keystrokes to the SC2 process so it
continuously pages through the arcade lobby list, triggering .s2ml cache
downloads that sc2_cache_monitor.py picks up.

Runs in the background — does NOT need SC2 to be the active window.

Requirements:
  - SC2 must be open on the Custom Games / arcade browser screen
  - Terminal (or the app running this) needs Accessibility access:
      System Settings > Privacy & Security > Accessibility

Usage:
  python3 sc2_arcade_scroller.py              # default settings
  python3 sc2_arcade_scroller.py --interval 15 --pages 4
"""
import subprocess, time, sys, argparse

SC2_PROCESS   = "SC2"
DEFAULT_INTERVAL = 20    # seconds between scroll bursts
DEFAULT_PAGES    = 3     # page downs per burst before resetting
KEY_PAGE_DOWN    = 121
KEY_PAGE_UP      = 116

def is_sc2_running() -> bool:
    r = subprocess.run(
        ["osascript", "-e",
         f'tell application "System Events" to get name of every process whose name is "{SC2_PROCESS}"'],
        capture_output=True, text=True)
    return SC2_PROCESS in r.stdout

def send_key(key_code: int, count: int = 1, delay: float = 0.15):
    """Activate SC2, send keystrokes, then restore the previously active app."""
    script = f'''
set previousApp to name of (info for (path to frontmost application))
tell application "{SC2_PROCESS}" to activate
delay 0.3
tell application "System Events"
    tell process "{SC2_PROCESS}"
        repeat {count} times
            key code {key_code}
            delay {delay}
        end repeat
    end tell
end tell
delay 0.2
try
    tell application previousApp to activate
end try
'''
    result = subprocess.run(["osascript", "-e", script],
                            capture_output=True, text=True)
    if result.returncode != 0:
        err = result.stderr.strip()
        if "not allowed" in err.lower() or "accessibility" in err.lower():
            print("[!] Accessibility permission denied.")
            print("    Go to: System Settings > Privacy & Security > Accessibility")
            print("    Add Terminal (or whatever is running this script) to the list.")
            return False
        if err:
            print(f"[warn] osascript: {err[:100]}")
    return result.returncode == 0

def scroll_burst(pages: int):
    """Page down N times, pause, then page back up."""
    ok = send_key(KEY_PAGE_DOWN, count=pages)
    if not ok:
        return False
    time.sleep(0.5)
    send_key(KEY_PAGE_UP, count=pages)
    return True

def main():
    parser = argparse.ArgumentParser(description="SC2 Arcade Auto-Scroller")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help=f"Seconds between scroll bursts (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--pages", type=int, default=DEFAULT_PAGES,
                        help=f"Page-downs per burst (default: {DEFAULT_PAGES})")
    parser.add_argument("--down-only", action="store_true",
                        help="Don't page back up (keeps advancing through the list)")
    args = parser.parse_args()

    print(f"[+] SC2 Arcade Auto-Scroller")
    print(f"[+] Interval: {args.interval}s  |  Pages per burst: {args.pages}")
    print(f"[+] SC2 must be on the Custom Games / arcade browser screen")
    print()

    if not is_sc2_running():
        print("[!] SC2 is not running. Start SC2 and go to Custom Games first.")
        sys.exit(1)

    print(f"[+] SC2 found. Starting scroll loop...")
    print(f"[!] Ctrl+C to stop")
    print()

    page_position = 0
    bursts = 0

    while True:
        if not is_sc2_running():
            print("[!] SC2 is no longer running. Waiting...")
            time.sleep(10)
            continue

        if args.down_only:
            ok = send_key(KEY_PAGE_DOWN, count=args.pages)
            page_position += args.pages
        else:
            ok = scroll_burst(args.pages)

        if ok:
            bursts += 1
            print(f"[scroll] burst #{bursts}  page_pos≈{page_position}  "
                  f"({time.strftime('%H:%M:%S')})")

        time.sleep(args.interval)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
