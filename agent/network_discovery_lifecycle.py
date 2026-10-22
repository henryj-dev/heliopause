"""Independent scheduler. Child collection/upload has no policy-agent locks or state access."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def _terminate(proc):
    # The session leader can exit before one of its collectors. Its dedicated process
    # group still belongs to this attempt; clean it even after poll() reaped the leader.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def run_once(stop, command, budget=45):
    """Bound the entire collector/parser/TLS process, not only individual commands."""
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + budget
    try:
        while proc.poll() is None:
            if stop.wait(min(.1, max(0, deadline - time.monotonic()))) or time.monotonic() >= deadline:
                return False
        return proc.returncode == 0
    finally:
        _terminate(proc)


def start_discovery_worker(stop, *, enabled=False, interval=300, budget=45, result=None):
    """Returns immediately; failed attempts wait a full interval before retrying."""
    if not enabled:
        return None
    if not 60 <= interval <= 86400 or not 5 <= budget <= 120:
        raise ValueError("invalid discovery schedule")
    command = [sys.executable, str(Path(__file__).with_name("network_discovery_worker.py"))]

    def loop():
        while not stop.is_set():
            try:
                ok = run_once(stop, command, budget)
                if result is not None:
                    result(ok)
            except (OSError, subprocess.SubprocessError):
                if result is not None:
                    result(False)
            stop.wait(interval)

    thread = threading.Thread(target=loop, name="network-discovery", daemon=True)
    thread.start()
    return thread
