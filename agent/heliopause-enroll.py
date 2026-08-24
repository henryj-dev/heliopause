#!/usr/bin/env python3
"""Enroll one pull agent without moving its private key off the host.

One invocation advances the durable state machine once: create key+CSR, submit idempotently, poll,
or install a signed certificate. A systemd timer retries it; pending approval is exit 75, not a
failure that destroys or regenerates the CSR.
"""

import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

URL = os.environ.get("HELIOPAUSE_ENROLL_URL", "").rstrip("/")
HOST_ID = os.environ.get("HELIOPAUSE_HOST_ID", "")
TOKEN_FILE = os.environ.get("HELIOPAUSE_ENROLL_TOKEN_FILE", "/etc/heliopause/enroll-token")
PKI_DIR = os.environ.get("HELIOPAUSE_PKI_DIR", "/etc/heliopause/pki")
# The expected anchor, distributed out of band beside the enrollment token.
#
# ## What this closes
#
# `verify_certificate` checks the leaf against the CA **the same response supplied**, and `install`
# then writes that CA to `ca.pem` — the anchor this host uses to verify its relay for the rest of its
# life. That is a self-consistency check, not a binding to our PKI: a response carrying a matching
# leaf/CA pair passes it whoever produced them.
#
# What binds it today is public WebPKI on the enrollment name plus the bearer token. There is no
# out-of-band fingerprint, so anyone who can obtain a certificate for that name, or terminate it,
# chooses the trust anchor for a fleet host. This file is that fingerprint.
#
# **Staged.** A missing pin is currently accepted, so the check can be deployed before the pins are —
# doing it the other way round stops every enrollment at once. Once the file is on every host this
# becomes a hard requirement; see `check_ca_pin`.
CA_PIN_FILE = os.environ.get("HELIOPAUSE_ENROLL_CA_PIN_FILE", "/etc/heliopause/enroll-ca-sha256")
#: Set to "1" to make a missing pin fatal — stage two of the rollout above.
CA_PIN_REQUIRED = os.environ.get("HELIOPAUSE_ENROLL_CA_PIN_REQUIRED", "") == "1"
STATE_FILE = os.environ.get("HELIOPAUSE_ENROLL_STATE_FILE", "/var/lib/heliopause-agent/enrollment.json")
OPENSSL = os.environ.get("HELIOPAUSE_OPENSSL_BIN", "/usr/bin/openssl")
NAME_OK = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$")
MAX_RESPONSE_BYTES = 64 * 1024
# The whole exchange, not each socket operation — see `read_json_response`.
HTTP_TIMEOUT_SEC = 15


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Enrollment credentials are never forwarded to another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run(args, data=None):
    try:
        p = subprocess.run([OPENSSL] + args, input=data, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"cannot run openssl: {e}") from e
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).decode("utf-8", "replace").strip())
    return p.stdout


def atomic_write(path, data, mode):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".enroll-", dir=os.path.dirname(path))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def read_json_response(res, deadline=None):
    """Parse the dispatcher's answer, bounded in size and — with a deadline — in time.

    ## The size bound was here; the time bound was not

    `timeout=` on the opener is a **socket** timeout: Python applies it per operation, so every byte
    that arrives resets it. A dispatcher answering one byte at a time filled the 64 KiB ceiling in
    about eleven days without ever tripping a fifteen-second timeout, and this command is what an
    installer runs and watches.

    The ceiling is the reason the damage was bounded at all, which is a different thing from the
    wait being bounded. Reading in pieces and consulting the clock between them makes the second one
    true as well. `deadline` is optional so the error paths below, which have already read their
    body, keep working unchanged.
    """
    declared = res.headers.get("Content-Length")
    if declared:
        try:
            if int(declared) > MAX_RESPONSE_BYTES:
                raise RuntimeError("enrollment response exceeds 64 KiB")
        except ValueError as e:
            raise RuntimeError("enrollment response has an invalid Content-Length") from e
    limit = MAX_RESPONSE_BYTES + 1
    raw = bytearray()
    while len(raw) < limit:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RuntimeError(f"enrollment response did not finish within {HTTP_TIMEOUT_SEC}s")
            _set_socket_timeout(res, left)
        piece = res.read(min(8192, limit - len(raw)))
        if not piece:
            break
        raw += piece
    raw = bytes(raw)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("enrollment response exceeds 64 KiB")
    value = json.loads(raw or b"{}")
    if not isinstance(value, dict):
        raise RuntimeError("enrollment response must be a JSON object")
    return value


def _set_socket_timeout(res, seconds):
    """Re-arm the response's socket, if this response has one to re-arm.

    `urllib` hands back an `http.client.HTTPResponse` whose socket is reachable but not part of any
    interface that promises to stay put. A best-effort re-arm is right here: failing to shorten the
    socket does not make the deadline check above stop working — the loop still gives up on the next
    pass — it only means the current `read` may block for the socket timeout first.
    """
    sock = getattr(getattr(res, "fp", None), "raw", None)
    sock = getattr(sock, "_sock", None)
    if sock is not None:
        try:
            sock.settimeout(seconds)
        except OSError:
            pass


def request(method, path, token, body=None):
    raw = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=raw, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
    })
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    deadline = time.monotonic() + HTTP_TIMEOUT_SEC
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT_SEC) as res:
            return res.status, read_json_response(res, deadline)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"enrollment redirect refused ({e.code})") from e
        return e.code, read_json_response(e)


def ensure_material():
    key = os.path.join(PKI_DIR, "agent.key")
    csr = os.path.join(PKI_DIR, "agent.csr.pem")
    os.makedirs(PKI_DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(key):
        fd, tmp = tempfile.mkstemp(prefix=".agent-key-", dir=PKI_DIR)
        os.close(fd)
        try:
            os.chmod(tmp, 0o600)
            run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-pkeyopt", "ec_param_enc:named_curve", "-out", tmp])
            os.replace(tmp, key)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    os.chmod(key, 0o600)
    if not os.path.exists(csr):
        pem = run(["req", "-new", "-key", key, "-subj", f"/CN={HOST_ID}"])
        atomic_write(csr, pem, 0o644)
    der = run(["req", "-in", csr, "-outform", "DER"])
    return key, csr, hashlib.sha256(der).hexdigest()


def check_ca_pin(ca_bytes):
    """Refuse an anchor that is not the one this host was told to expect.

    The pin is the SHA-256 of the CA's **DER** bytes, not of its PEM text: PEM carries line endings
    and optional trailing whitespace, and two files that differ only there are the same certificate.
    Compared as lowercase hex, which is what `openssl dgst` and every other tool here prints.

    A missing pin is accepted while the file is being distributed, and refused once
    `HELIOPAUSE_ENROLL_CA_PIN_REQUIRED=1`. Both states are deliberate and only one of them is the
    end state — see `CA_PIN_FILE`.
    """
    try:
        with open(CA_PIN_FILE, "r", encoding="ascii") as f:
            expected = f.read().strip().lower()
    except FileNotFoundError:
        if CA_PIN_REQUIRED:
            raise RuntimeError(f"no enrollment CA pin at {CA_PIN_FILE} and one is required")
        return
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError(f"the enrollment CA pin at {CA_PIN_FILE} is not a sha256 hex digest")
    der = run(["x509", "-outform", "DER"], ca_bytes)
    actual = hashlib.sha256(der).hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"enrollment CA {actual} does not match the pinned anchor {expected} — refusing to "
            f"install a trust anchor this host was not told to expect"
        )


def install(bundle, key):
    cert = bundle.get("certificatePem", "").encode()
    ca = bundle.get("caPem", "").encode()
    if not cert or not ca:
        raise RuntimeError("certificate response is incomplete")
    # Before anything is written. `verify_certificate` below proves the leaf belongs to this CA; this
    # proves the CA is ours, and only the pair is worth anything.
    check_ca_pin(ca)
    with tempfile.TemporaryDirectory(prefix="heliopause-enroll-", dir=PKI_DIR) as d:
        cp, cap = os.path.join(d, "agent.pem"), os.path.join(d, "ca.pem")
        with open(cp, "wb") as f:
            f.write(cert)
        with open(cap, "wb") as f:
            f.write(ca)
        verify_certificate(cp, cap, key)
        atomic_write(os.path.join(PKI_DIR, "ca.pem"), ca, 0o644)
        atomic_write(os.path.join(PKI_DIR, "agent.pem"), cert, 0o644)


def verify_certificate(cert, ca, key):
    run(["verify", "-CAfile", ca, cert])
    subject = run(["x509", "-in", cert, "-noout", "-subject", "-nameopt", "RFC2253"]).decode().strip()
    # OpenSSL 3 prints `subject=CN=...`; macOS LibreSSL prints `subject= CN=...` even with
    # `-nameopt RFC2253`. Permit only that separator whitespace, not an additional subject field.
    if not re.fullmatch(r"subject=\s*CN=" + re.escape(HOST_ID), subject):
        raise RuntimeError(f"certificate subject mismatch: {subject}")
    cert_pub = run(["x509", "-in", cert, "-pubkey", "-noout"])
    key_pub = run(["pkey", "-in", key, "-pubout"])
    if cert_pub != key_pub:
        raise RuntimeError("certificate public key does not match local private key")


def main():
    if not URL.startswith("https://"):
        raise RuntimeError("HELIOPAUSE_ENROLL_URL must be https")
    if not NAME_OK.fullmatch(HOST_ID):
        raise RuntimeError("HELIOPAUSE_HOST_ID is invalid")
    key, csr, digest = ensure_material()
    state = load_json(STATE_FILE)
    if state and state.get("csr_sha256") != digest:
        raise RuntimeError("saved request belongs to a different CSR; refusing to create a conflict")
    if state and state.get("completed"):
        verify_certificate(os.path.join(PKI_DIR, "agent.pem"), os.path.join(PKI_DIR, "ca.pem"), key)
        print(f"certificate already installed for {HOST_ID}")
        return 0
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        token = f.read().strip()
    if not token.startswith("stnode_"):
        raise RuntimeError("enrollment token has the wrong shape")
    if not state:
        with open(csr, "r", encoding="ascii") as f:
            csr_pem = f.read()
        status, body = request("POST", "/infra/node-csrs", token, {"csrPem": csr_pem})
        if status not in (200, 201):
            raise RuntimeError(f"CSR submit failed ({status}): {body.get('error', '')}")
        req = body["request"]
        if req.get("csrSha256") != digest:
            raise RuntimeError("dispatcher returned a different CSR fingerprint")
        state = {"request_id": req["id"], "csr_sha256": digest}
        atomic_write(STATE_FILE, (json.dumps(state) + "\n").encode(), 0o600)
        print(f"CSR submitted: {req['id']} sha256={digest}")
    status, body = request("GET", f"/infra/node-csrs/{state['request_id']}/certificate", token)
    if status == 404:
        print(f"certificate pending: {state['request_id']} sha256={digest}")
        return 75
    if status != 200:
        raise RuntimeError(f"certificate fetch failed ({status}): {body.get('error', '')}")
    install(body["certificate"], key)
    state["completed"] = True
    atomic_write(STATE_FILE, (json.dumps(state) + "\n").encode(), 0o600)
    # The bearer has done its one job. Left in place it is valid for up to thirty days
    # (MAX_NODE_TOKEN_TTL_SEC) and can still submit a CSR for this hostname and fetch the certificate
    # that comes back — on a host whose private key is already here, which is the machine an attacker
    # would have to own to use it. Small, and there is no reason to keep it.
    #
    # Deleted after the state write, not before: if the unlink succeeds and the write then fails, the
    # next run has no token and no record of having finished, and the timer retries forever against a
    # credential that is gone.
    #
    # The unit's `ConditionPathExists=/etc/heliopause/enroll-token` then makes the timer a no-op
    # rather than a failure, which is the intended end state — re-enrolling means issuing a new token,
    # which is already the procedure.
    try:
        os.unlink(TOKEN_FILE)
    except OSError as e:
        # Not fatal. The certificate is installed and working; a token that could not be removed is
        # worth a line, not a non-zero exit that makes monitoring report a broken enrollment.
        print(f"[heliopause-enroll] could not remove the spent token {TOKEN_FILE}: {e}", file=sys.stderr)
    print(f"certificate installed for {HOST_ID}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[heliopause-enroll] {e}", file=sys.stderr)
        sys.exit(1)
