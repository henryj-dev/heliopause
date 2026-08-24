#!/usr/bin/env python3
"""Regression tests for host-local enrollment state and key custody."""

import importlib.util
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("heliopause_enroll", HERE / "heliopause-enroll.py")
enroll = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(enroll)


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.pki = root / "pki"
        self.state = root / "enrollment.json"
        self.token = root / "token"
        self.token.write_text("stnode_test-token\n", encoding="utf-8")
        self.settings = mock.patch.multiple(
            enroll,
            URL="https://dispatcher.example.com",
            HOST_ID="node-01.example",
            TOKEN_FILE=str(self.token),
            PKI_DIR=str(self.pki),
            STATE_FILE=str(self.state),
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def test_key_and_csr_are_reused_with_der_fingerprint(self):
        key, csr, digest = enroll.ensure_material()
        first_key = pathlib.Path(key).read_bytes()
        first_csr = pathlib.Path(csr).read_bytes()

        key2, csr2, digest2 = enroll.ensure_material()

        self.assertEqual((key, csr, digest), (key2, csr2, digest2))
        self.assertEqual(first_key, pathlib.Path(key).read_bytes())
        self.assertEqual(first_csr, pathlib.Path(csr).read_bytes())
        self.assertEqual(64, len(digest))
        self.assertEqual("subject=CN=node-01.example", enroll.run([
            "req", "-in", csr, "-noout", "-subject", "-nameopt", "RFC2253",
        ]).decode().strip())
        key_text = enroll.run(["pkey", "-in", key, "-text", "-noout"]).decode()
        # LibreSSL expands named curves instead of printing their OID; the requested P-256 size is
        # stable across it and OpenSSL, while the command itself rejects a non-EC key.
        self.assertIn("Private-Key: (256 bit)", key_text)

    def test_pending_request_is_persisted_and_not_submitted_twice(self):
        material = (str(self.pki / "agent.key"), str(self.pki / "agent.csr.pem"), "a" * 64)
        self.pki.mkdir()
        pathlib.Path(material[1]).write_text("CSR", encoding="ascii")
        calls = []

        def request(method, path, token, body=None):
            calls.append((method, path, body))
            if method == "POST":
                return 201, {"request": {"id": "req-1", "csrSha256": "a" * 64}}
            return 404, {"error": "pending"}

        with mock.patch.object(enroll, "ensure_material", return_value=material), \
             mock.patch.object(enroll, "request", side_effect=request):
            self.assertEqual(75, enroll.main())
            self.assertEqual(75, enroll.main())

        self.assertEqual(["POST", "GET", "GET"], [call[0] for call in calls])
        self.assertEqual({"request_id": "req-1", "csr_sha256": "a" * 64},
                         json.loads(self.state.read_text()))

    def test_install_marks_complete_and_next_run_is_offline(self):
        material = (str(self.pki / "agent.key"), str(self.pki / "agent.csr.pem"), "b" * 64)
        self.pki.mkdir()
        pathlib.Path(material[1]).write_text("CSR", encoding="ascii")
        self.state.write_text(json.dumps({"request_id": "req-2", "csr_sha256": "b" * 64}))
        response = {"certificate": {"certificatePem": "CERT", "caPem": "CA"}}

        with mock.patch.object(enroll, "ensure_material", return_value=material), \
             mock.patch.object(enroll, "request", return_value=(200, response)) as request, \
             mock.patch.object(enroll, "install") as install:
            self.assertEqual(0, enroll.main())
            install.assert_called_once_with(response["certificate"], material[0])
            request.assert_called_once()

        completed = json.loads(self.state.read_text())
        self.assertTrue(completed["completed"])
        # The bearer is spent. It stays valid for up to thirty days and can still submit a CSR for
        # this hostname, so there is no reason to leave it on the host — and the unit's
        # ConditionPathExists then makes the retry timer a no-op rather than a failure.
        self.assertFalse(self.token.exists(), "the spent enrollment token was left on the host")
        with mock.patch.object(enroll, "ensure_material", return_value=material), \
             mock.patch.object(enroll, "verify_certificate") as verify, \
             mock.patch.object(enroll, "request") as request:
            self.assertEqual(0, enroll.main())
            verify.assert_called_once()
            request.assert_not_called()

    def test_an_unremovable_token_does_not_fail_the_enrollment(self):
        """The certificate is installed and working; a token that will not unlink is a log line.

        Exiting non-zero here would make monitoring report a broken enrollment on a host that is
        fully enrolled, and the timer would keep retrying an operation that has already succeeded.
        """
        material = (str(self.pki / "agent.key"), str(self.pki / "agent.csr.pem"), "b" * 64)
        self.pki.mkdir()
        pathlib.Path(material[1]).write_text("CSR", encoding="ascii")
        self.state.write_text(json.dumps({"request_id": "req-3", "csr_sha256": "b" * 64}))
        response = {"certificate": {"certificatePem": "CERT", "caPem": "CA"}}

        real_unlink = os.unlink

        def only_the_token(path, *args, **kwargs):
            # Scoped to the token. Patching `os.unlink` wholesale also breaks `atomic_write`'s own
            # temp-file cleanup, and the test then fails for a reason that has nothing to do with
            # what it claims to check — which is how it failed the first time it was written.
            if str(path) == str(self.token):
                raise PermissionError("read-only")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(enroll, "ensure_material", return_value=material), \
             mock.patch.object(enroll, "request", return_value=(200, response)), \
             mock.patch.object(enroll, "install"), \
             mock.patch.object(enroll.os, "unlink", side_effect=only_the_token):
            self.assertEqual(0, enroll.main())

        self.assertTrue(json.loads(self.state.read_text())["completed"])
        # And the token is still there — the point is that this does not fail the run, not that it
        # silently succeeded.
        self.assertTrue(self.token.exists())

    def test_state_for_another_csr_is_rejected_before_network(self):
        self.state.write_text(json.dumps({"request_id": "req-old", "csr_sha256": "c" * 64}))
        material = ("key", "csr", "d" * 64)
        with mock.patch.object(enroll, "ensure_material", return_value=material), \
             mock.patch.object(enroll, "request") as request:
            with self.assertRaisesRegex(RuntimeError, "different CSR"):
                enroll.main()
            request.assert_not_called()

    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_redirect_is_refused_without_forwarding_bearer_token(self):
        received = []

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        target = self.serve(Target)

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/capture")
                self.end_headers()

            def log_message(self, *_args):
                pass

        source = self.serve(Redirect)
        with mock.patch.object(enroll, "URL", f"http://127.0.0.1:{source.server_port}"):
            with self.assertRaisesRegex(RuntimeError, "redirect refused"):
                enroll.request("GET", "/start", "stnode_do-not-forward")
        self.assertEqual([], received)

    def test_response_body_is_bounded(self):
        body = b'{"value":"' + (b"x" * enroll.MAX_RESPONSE_BYTES) + b'"}'

        class Oversized(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        source = self.serve(Oversized)
        with mock.patch.object(enroll, "URL", f"http://127.0.0.1:{source.server_port}"):
            with self.assertRaisesRegex(RuntimeError, "exceeds 64 KiB"):
                enroll.request("GET", "/oversized", "stnode_test")




class CaPinTests(unittest.TestCase):
    """The installed anchor must be the one this host was told to expect.

    ## What was missing

    `verify_certificate` checks the leaf against the CA the **same response** supplied, and `install`
    then writes that CA as `ca.pem` — the anchor this host uses to verify its relay from then on. A
    matching leaf/CA pair passes that check whoever made them, so the only thing binding the anchor
    to our PKI was public WebPKI on the enrollment name plus a bearer token.

    The pin is over DER, not PEM: two files differing only in line endings are the same certificate.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.pin = root / "pin"
        self.ca_pem = root / "ca.pem"
        self.other_pem = root / "other.pem"
        for path, cn in ((self.ca_pem, "hp-ca"), (self.other_pem, "somebody-else")):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", str(root / f"{cn}.key"), "-out", str(path), "-subj", f"/CN={cn}"],
                check=True, capture_output=True,
            )
        self.settings = mock.patch.multiple(enroll, CA_PIN_FILE=str(self.pin), CA_PIN_REQUIRED=False)
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def _digest(self, pem_path):
        der = subprocess.run(["openssl", "x509", "-in", str(pem_path), "-outform", "DER"],
                             check=True, capture_output=True).stdout
        return hashlib.sha256(der).hexdigest()

    def test_the_matching_anchor_is_accepted(self):
        # The known positive. Without it every refusal below passes against a function that rejects
        # everything, which would stop enrollment entirely and look like the check working.
        self.pin.write_text(self._digest(self.ca_pem) + "\n", encoding="ascii")
        enroll.check_ca_pin(self.ca_pem.read_bytes())

    def test_a_different_anchor_is_refused(self):
        self.pin.write_text(self._digest(self.ca_pem), encoding="ascii")
        with self.assertRaises(RuntimeError) as caught:
            enroll.check_ca_pin(self.other_pem.read_bytes())
        self.assertIn("does not match the pinned anchor", str(caught.exception))

    def test_a_missing_pin_is_accepted_while_it_is_being_distributed(self):
        # Stage one. Making it fatal before the file exists everywhere stops every enrollment at once.
        enroll.check_ca_pin(self.ca_pem.read_bytes())

    def test_a_missing_pin_is_fatal_once_required(self):
        # Stage two, and the end state. Until this is switched on the check is only half deployed —
        # which is worth being able to assert rather than remember.
        with mock.patch.object(enroll, "CA_PIN_REQUIRED", True):
            with self.assertRaises(RuntimeError) as caught:
                enroll.check_ca_pin(self.ca_pem.read_bytes())
        self.assertIn("required", str(caught.exception))

    def test_a_malformed_pin_is_refused_rather_than_ignored(self):
        # A truncated or edited pin must not read as "no pin". That would turn a corrupted file into
        # a silently disabled check — the failure this repository keeps finding.
        self.pin.write_text("not-a-digest", encoding="ascii")
        with self.assertRaises(RuntimeError) as caught:
            enroll.check_ca_pin(self.ca_pem.read_bytes())
        self.assertIn("not a sha256", str(caught.exception))

    def test_install_checks_the_pin_before_writing_anything(self):
        # The anchor is written by `install`. A check that ran after the write would leave the wrong
        # ca.pem on disk for whatever reads it next.
        self.pin.write_text(self._digest(self.ca_pem), encoding="ascii")
        pki = pathlib.Path(self.tmp.name) / "pki"
        pki.mkdir()
        with mock.patch.object(enroll, "PKI_DIR", str(pki)):
            with self.assertRaises(RuntimeError) as caught:
                enroll.install(
                    {"certificatePem": "CERT", "caPem": self.other_pem.read_text()}, "key")
        # The **reason**, not just that it raised. `verify_certificate` runs a few lines later and
        # would also reject this fixture, so asserting the type alone passes with the pin check
        # deleted — measured by defect injection, which is the only way that shows.
        self.assertIn("does not match the pinned anchor", str(caught.exception))
        self.assertFalse((pki / "ca.pem").exists(), "the refused anchor was written anyway")


class ResponseDeadlineTests(unittest.TestCase):
    """The answer is bounded in time as well as in size.

    `timeout=` on the opener is a **socket** timeout: Python applies it per operation, so every byte
    that arrives resets it. The 64 KiB ceiling meant the damage was bounded — a dispatcher answering
    one byte at a time filled it in about eleven days — which is a different thing from the wait
    being bounded, and this is the command an installer runs and watches.
    """

    class _Res:
        """A response that hands back one byte at a time and records every socket re-arm."""

        def __init__(self, clock, per_read=1):
            self.headers = {}
            self.armed = []
            self._clock = clock
            self._per_read = per_read

        def read(self, n):
            # Each read costs a second of the deadline, which is what a trickling peer does.
            self._clock.advance(1)
            return b"x" * min(n, self._per_read)

    class _Clock:
        def __init__(self):
            self.now = 0.0

        def advance(self, by):
            self.now += by

    def test_a_trickling_response_is_given_up_on(self):
        clock = self._Clock()
        real = enroll.time.monotonic
        enroll.time.monotonic = lambda: clock.now
        try:
            deadline = clock.now + enroll.HTTP_TIMEOUT_SEC
            with self.assertRaises(RuntimeError) as caught:
                enroll.read_json_response(self._Res(clock), deadline)
        finally:
            enroll.time.monotonic = real
        self.assertIn(f"within {enroll.HTTP_TIMEOUT_SEC}s", str(caught.exception))
        # Given up on the clock, not on the ceiling — those are different failures and the message
        # is what tells an installer which.
        self.assertNotIn("64 KiB", str(caught.exception))

    def test_a_prompt_response_still_parses(self):
        # The known positive. Without it, a reader that gave up immediately would pass the test above
        # and make every enrolment fail.
        class Prompt:
            headers = {}

            def __init__(self):
                self._sent = False

            def read(self, n):
                if self._sent:
                    return b""
                self._sent = True
                return b'{"ok": true}'

        self.assertEqual(enroll.read_json_response(Prompt(), None), {"ok": True})

    def test_the_size_ceiling_still_wins_when_there_is_time(self):
        # The other bound, unchanged. A dispatcher that answers quickly and enormously is refused for
        # its size, and says so.
        class Flood:
            headers = {}

            def read(self, n):
                return b"x" * n

        with self.assertRaises(RuntimeError) as caught:
            enroll.read_json_response(Flood(), None)
        self.assertIn("64 KiB", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
