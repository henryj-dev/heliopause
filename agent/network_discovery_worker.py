#!/usr/bin/env python3
"""Opt-in isolated telemetry worker. Never imports the policy agent or confirms a generation."""
import hashlib
import http.client
import json
import os
import ssl
import socket
import signal
import time
import urllib.parse
import uuid
from network_discovery import collect_network_state

MAX_REPORT_BYTES = 128 * 1024 - 1024


def collect_report():
    report = collect_network_state(timeout=2.0, total_timeout=30.0, output_limit=128 * 1024)
    report["collectionId"] = str(uuid.uuid4())
    if len(json.dumps(report).encode()) > MAX_REPORT_BYTES:
        # Preserve per-collector failure evidence rather than silently truncating routes/peers.
        for result in report["observations"].values():
            if result["status"] == "success":
                result.pop("data", None)
                result["status"] = "output-limit"
        for name, result in report["observations"].items():
            report["capabilities"][name] = {"available": False, "status": result["status"]}
    return report


def upload(report):
    parts = urllib.parse.urlsplit(os.environ["HELIOPAUSE_RELAY_URL"])
    if parts.scheme != "https":
        raise ValueError("https relay required")
    context = ssl.create_default_context(cafile=os.environ["HELIOPAUSE_CA_FILE"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ["HELIOPAUSE_CERT_FILE"], os.environ["HELIOPAUSE_KEY_FILE"])
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=5)
    try:
        conn.connect()
        # Match agent relay pinning; a valid CA alone is not an excuse to omit configured pins.
        pins = os.environ.get("HELIOPAUSE_PINS", "").split(",")
        pins = [pin.strip().removeprefix("sha256/") for pin in pins if pin.strip()]
        if pins:
            import base64
            der = conn.sock.getpeercert(binary_form=True)
            digest = base64.b64encode(hashlib.sha256(der).digest()).decode()
            if digest not in pins:
                raise ssl.SSLCertVerificationError("relay pin mismatch")
        body = json.dumps({"host": (os.environ.get("HELIOPAUSE_HOST_ID") or socket.gethostname()), "report": report}).encode()
        if len(body) > 128 * 1024:
            raise ValueError("observation upload too large")
        conn.request("POST", parts.path.rstrip("/") + "/network/observations", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError("observation upload refused")
        if len(response.read(4097)) > 4096:
            raise ValueError("observation response too large")
    finally:
        conn.close()


def _hard_deadline(*_):
    # The scheduler starts a dedicated session. Never signal a caller's foreground
    # group when this library/CLI was invoked without that isolation.
    if os.getsid(0) == os.getpid() and os.getpgrp() == os.getpid():
        os.killpg(os.getpid(), signal.SIGKILL)
    os._exit(1)


def main():
    # The parent watchdog disappears on an abrupt agent restart. Keep a second hard deadline
    # inside this single-purpose process so a slow TLS peer cannot leave an orphan uploader.
    signal.signal(signal.SIGALRM, _hard_deadline)
    signal.alarm(40)
    try:
        upload(collect_report())
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No raw subprocess output, endpoints, keys or server diagnostics in service logs.
        raise SystemExit(1)
