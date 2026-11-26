from datetime import datetime, time, timedelta, timezone
from http.client import IncompleteRead
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
CHECK_HOURS = range(5, 24, 3)


def due_slot(now):
    local = now.astimezone(SHANGHAI)
    hour = next((hour for hour in reversed(CHECK_HOURS) if local.time() >= time(hour, 30)), None)
    day = local.date() if hour is not None else local.date() - timedelta(days=1)
    return f"{day}T{hour if hour is not None else CHECK_HOURS[-1]:02d}:30"


def publish_slot(stop, slot):
    command = [sys.executable, "-m", "prm_release", "publish", "--slot", slot]
    for attempt in range(2):
        try:
            result = subprocess.run(command, timeout=840)
        except subprocess.TimeoutExpired:
            print("Scheduled publication reached its timeout", flush=True)
            return
        print(f"Scheduled publication exited with status {result.returncode}", flush=True)
        if result.returncode != prm_release.TEMPORARY_FAILURE or attempt == 1 or stop.wait(30):
            return
        try:
            if prm_release.api("updates/current", timeout=5) is not None:
                return
        except (URLError, TimeoutError, ConnectionError, IncompleteRead, RuntimeError):
            return
        print("Retrying transient rule publication failure", flush=True)


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
        except (URLError, TimeoutError, ConnectionError, IncompleteRead, RuntimeError):
            stop.wait(5)
    while not stop.is_set():
        slot = due_slot(datetime.now(timezone.utc))
        if not marker.exists() or marker.read_text().strip() < slot:
            print(f"Scheduled publication for {slot} Asia/Shanghai", flush=True)
            publish_slot(stop, slot)
            pending = marker.with_suffix(".scheduled-slot.tmp")
            pending.write_text(slot + "\n")
            pending.replace(marker)
        stop.wait(15)


if __name__ == "__main__":
    main()
