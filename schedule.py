from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
import os
from pathlib import Path
import signal
import subprocess
import sys
from threading import Event
from urllib.error import URLError
from zoneinfo import ZoneInfo

from configuration import schedule_settings
import prm_release


MARKER_ZONE = ZoneInfo("Asia/Shanghai")
SLOT_FORMAT = "%Y-%m-%dT%H:%M"


def due_slot(now, zone, slots):
    day = now.astimezone(zone).date()
    for offset in range(3):
        for slot in reversed(slots):
            local = datetime.combine(day - timedelta(days=offset), slot, zone)
            instant = local.astimezone(timezone.utc)
            if instant <= now and instant.astimezone(zone).replace(tzinfo=None) == local.replace(tzinfo=None):
                return local
    raise ValueError("No scheduled slot in the last three local calendar days")


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
    try:
        enabled, zone, slots = schedule_settings(os.environ)
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if not enabled:
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
        slot = due_slot(datetime.now(timezone.utc), zone, slots)
        # Keep the on-disk marker in the previous release's fixed clock.
        recorded = slot.astimezone(MARKER_ZONE).strftime(SLOT_FORMAT)
        prior = marker.read_text().strip() if marker.exists() else ""
        if prior:
            datetime.strptime(prior, SLOT_FORMAT)
        if prior < recorded:
            print(f"Scheduled publication for {slot.strftime(SLOT_FORMAT)} {zone.key}", flush=True)
            publish_slot(stop, slot.strftime(SLOT_FORMAT))
            pending = marker.with_suffix(".scheduled-slot.tmp")
            pending.write_text(recorded + "\n")
            pending.replace(marker)
        stop.wait(15)


if __name__ == "__main__":
    main()
