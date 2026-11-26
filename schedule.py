from datetime import datetime, time, timedelta, timezone
import os
from pathlib import Path
import signal
import subprocess
import sys
from threading import Event
from urllib.error import URLError
from zoneinfo import ZoneInfo

import prm_release


SHANGHAI = ZoneInfo("Asia/Shanghai")
DAILY = time(5, 30)


def due_slot(now):
    local = now.astimezone(SHANGHAI)
    return (local.date() if local.time() >= DAILY else local.date() - timedelta(days=1)).isoformat()


def main():
    stop = Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    if os.environ.get("PUBLISH_SCHEDULE_ENABLED", "1") != "1":
        print("Scheduled publication disabled", flush=True)
        stop.wait()
        return
    state = Path(os.environ.get("RULES_STATE", "/data/state"))
    marker = state / ".scheduled-slot"
    while not stop.is_set():
        try:
            prm_release.api("config", timeout=5)
            break
        except (URLError, TimeoutError, RuntimeError):
            stop.wait(5)
    while not stop.is_set():
        slot = due_slot(datetime.now(timezone.utc))
        if not marker.exists() or marker.read_text().strip() < slot:
            print(f"Scheduled publication for {slot} 05:30 Asia/Shanghai", flush=True)
            try:
                result = subprocess.run([sys.executable, "-m", "prm_release", "publish"], timeout=840)
                print(f"Scheduled publication exited with status {result.returncode}", flush=True)
            except subprocess.TimeoutExpired:
                print("Scheduled publication reached its timeout", flush=True)
            pending = marker.with_suffix(".scheduled-slot.tmp")
            pending.write_text(slot + "\n")
            pending.replace(marker)
        stop.wait(15)


if __name__ == "__main__":
    main()
