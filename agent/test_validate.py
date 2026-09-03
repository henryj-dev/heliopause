#!/usr/bin/env python3
"""Tests for the agent's artifact validator.

Every case here is an attempt to make the agent touch something that is not its own table. The
first group is the security audit's findings, restated in the artifact format that replaced the
one they were found in — they are kept as tests rather than deleted as fixed, because the class of
bug ("the validator can be talked past") is what matters, not the specific syntax.

    python3 agent/test_validate.py
"""

import atexit
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HELIOPAUSE_RELAY_URL", "https://unused.invalid")
# The agent persists state on rollback. Point it at a scratch file so the suite never touches
# /var/lib and never depends on the caller exporting anything.
_STATE = tempfile.NamedTemporaryFile(prefix="heliopause-test-state-", suffix=".json", delete=False)
_STATE.close()
os.environ["HELIOPAUSE_STATE_FILE"] = _STATE.name
_KUBECONFIG = tempfile.NamedTemporaryFile(prefix="heliopause-test-kubeconfig-", delete=False)
_KUBECONFIG.close()
os.chmod(_KUBECONFIG.name, 0o600)
os.environ["HELIOPAUSE_KUBECONFIG"] = _KUBECONFIG.name
os.environ["HELIOPAUSE_K8S_NAMESPACES"] = "util,arc-runners,idp,x,broken,fine"
atexit.register(lambda: os.path.exists(_STATE.name) and os.unlink(_STATE.name))
atexit.register(lambda: os.path.exists(_KUBECONFIG.name) and os.unlink(_KUBECONFIG.name))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "hp_agent", os.path.join(os.path.dirname(os.path.abspath(__file__)), "heliopause-pull.py")
)
hp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hp)

TABLE = {"family": "inet", "name": "heliopause"}

# ## Why verification is stubbed for the rollback-ordering suites below
#
# Those tests hand `fetch_artifact` a plain artifact and are about **what the apply path does with
# it** — arming, ordering, rollback. Once the signed path was wired in, the plain dict stopped being
# an envelope and six of them failed for a reason none of them is about.
#
# The seam itself is covered by `TestSignedArtifactSeam`, which asserts the apply path calls the
# verifier before it reads a generation and records the replay watermark before any side effect.
# What is **not** covered here is `verify_artifact_envelope`'s own behaviour — that needs key
# fixtures, and its absence is the reason the missing call went unnoticed for a fleet-wide rollout.
def stub_artifact_verification():
    """Make the apply path treat a plain artifact as an already-verified one. Returns a restore fn."""
    real = (hp.verify_artifact_envelope, hp.accept_artifact_authorization)
    hp.verify_artifact_envelope = lambda envelope, now=None: (
        envelope,
        {"authorizedAt": "2026-01-01T00:00:00.000Z", "generation": envelope.get("generation")},
        None,
        False,
    )
    hp.accept_artifact_authorization = lambda record, watch, expired: ({}, "")

    def restore():
        hp.verify_artifact_envelope, hp.accept_artifact_authorization = real

    return restore


_RESTORE_VERIFICATION = stub_artifact_verification()




def doc(*commands):
    return json.dumps({"nftables": list(commands)})


def rule(family="inet", table="heliopause", chain="input"):
    return {"add": {"rule": {"family": family, "table": table, "chain": chain, "expr": [{"drop": None}]}}}


def chain(hook="input", ctype="filter", table="heliopause"):
    return {
        "add": {
            "chain": {
                "family": "inet", "table": table, "name": "c",
                "type": ctype, "hook": hook, "prio": 0, "policy": "accept",
            }
        }
    }


VALID = doc({"add": {"table": TABLE}}, {"delete": {"table": TABLE}}, {"add": {"table": TABLE}},
            chain(), rule())
VALID_HASH = "sha256:" + hp.hashlib.sha256(VALID.encode()).hexdigest()


class TestAcceptsRealArtifacts(unittest.TestCase):
    def test_accepts_a_well_formed_artifact(self):
        parsed, reason = hp.validate_artifact(VALID)
        self.assertIsNotNone(parsed, reason)

    def test_accepts_the_output_hook(self):
        parsed, reason = hp.validate_artifact(doc(chain(hook="output")))
        self.assertIsNotNone(parsed, reason)

    def test_accepts_a_chain_with_no_hook(self):
        # Regular (non-base) chains carry no hook. Rejecting them would forbid jump targets.
        parsed, reason = hp.validate_artifact(
            doc({"add": {"chain": {"family": "inet", "table": "heliopause", "name": "helper"}}})
        )
        self.assertIsNotNone(parsed, reason)


class TestAuditFindings(unittest.TestCase):
    """C-1, H-1 and M-7 from the security audit, in the current artifact format."""

    def test_c1_refuses_a_rule_in_another_table(self):
        # The original bypass: the old validator only inspected statements beginning with `table`,
        # so `add rule ip filter INPUT drop` was never examined at all.
        parsed, reason = hp.validate_artifact(doc(rule(family="ip", table="filter")))
        self.assertIsNone(parsed)
        self.assertIn("family", reason)

    def test_c1_refuses_a_rule_in_another_inet_table(self):
        parsed, reason = hp.validate_artifact(doc(rule(table="firewalld")))
        self.assertIsNone(parsed)
        self.assertIn("firewalld", reason)

    def test_c1_refuses_deleting_someone_elses_table(self):
        # Worth its own case: `delete` is on the allowlist because the agent replaces its own table
        # with it, and an unscoped delete would remove firewalld's ruleset outright.
        parsed, reason = hp.validate_artifact(
            doc({"delete": {"table": {"family": "ip", "name": "filter"}}})
        )
        self.assertIsNone(parsed)

    def test_h1_refuses_flush(self):
        # `flush ruleset` was reachable in the old validator by writing it after a `;`, which moved
        # it off the line start its regex was anchored to. Here the verb itself is not allowed.
        parsed, reason = hp.validate_artifact(doc({"flush": {"ruleset": None}}))
        self.assertIsNone(parsed)
        self.assertIn("flush", reason)

    def test_m7_refuses_a_nat_chain_in_our_own_table(self):
        # Inside our table, so the table check passes — the chain type is what stops it. A nat
        # chain rewrites addresses for traffic this agent does not own.
        parsed, reason = hp.validate_artifact(doc(chain(ctype="nat", hook="output")))
        self.assertIsNone(parsed)
        self.assertIn("nat", reason)

    def test_accepts_the_forward_hook(self):
        # This asserted the opposite until 2026-08-02, on the reasoning that forward puts the agent
        # in the path of routed traffic — containers, VMs, anything the host gateways for — and was
        # therefore out of scope. That reasoning was right about the risk and wrong about the scope.
        #
        # Measured on three gateways: firewalld's forward chain was refusing
        # `public interface -> VPC` and `public interface -> wireguard`, and heliopause filtered
        # neither. So "heliopause is the only firewall" could not be true on a router without it,
        # and retiring firewalld would have opened a path from the provider's shared public segment
        # into the VPC and into the mesh.
        #
        # The risk did not go away, it moved into the renderer: the forward chain is fixed and small
        # rather than policy-driven, and its chain policy is always accept. See `ForwardConfig`.
        parsed, _ = hp.validate_artifact(doc(chain(hook="forward")))
        self.assertIsNotNone(parsed)

    def test_still_refuses_a_nat_chain_on_the_forward_hook(self):
        # Allowing the hook is not allowing the chain type. A nat chain rewrites addresses for
        # traffic this agent does not own, and that is refused on every hook.
        parsed, reason = hp.validate_artifact(doc(chain(ctype="nat", hook="forward")))
        self.assertIsNone(parsed)
        self.assertIn("nat", reason)

    def test_refuses_prerouting(self):
        parsed, reason = hp.validate_artifact(doc(chain(hook="prerouting")))
        self.assertIsNone(parsed)


class TestMalformed(unittest.TestCase):
    def test_refuses_non_json(self):
        parsed, reason = hp.validate_artifact("table inet heliopause {}")
        self.assertIsNone(parsed)
        self.assertIn("JSON", reason)

    def test_refuses_a_document_without_nftables(self):
        parsed, _ = hp.validate_artifact(json.dumps({"rules": []}))
        self.assertIsNone(parsed)

    def test_refuses_an_empty_command_list(self):
        # An empty artifact would apply cleanly and leave the host with no rules, which reads as
        # success while enforcing nothing.
        parsed, _ = hp.validate_artifact(doc())
        self.assertIsNone(parsed)

    def test_refuses_two_verbs_in_one_command(self):
        # Smuggling: a permitted verb next to a forbidden one in the same object.
        parsed, _ = hp.validate_artifact(
            json.dumps({"nftables": [{"add": {"table": TABLE}, "flush": {"ruleset": None}}]})
        )
        self.assertIsNone(parsed)

    def test_refuses_an_unknown_object_kind(self):
        # The allowlist is closed, so an nft feature this agent has never heard of arrives as a
        # refused generation rather than as a surprise capability.
        parsed, _ = hp.validate_artifact(doc({"add": {"set": {"family": "inet", "table": "heliopause"}}}))
        self.assertIsNone(parsed)

    def test_refuses_a_missing_family(self):
        parsed, _ = hp.validate_artifact(doc({"add": {"rule": {"table": "heliopause", "chain": "input"}}}))
        self.assertIsNone(parsed)


class TestRollbackStateMachine(unittest.TestCase):
    """The backup slot has three states and they must not collapse into two.

    `None` means "we captured a backup and there was no table then" — restoring deletes.
    `_NO_BACKUP` means "we captured nothing" — restoring must do nothing at all. Conflating them
    makes a second rollback delete the live ruleset, which is the opposite of what rollback is for.
    """

    def setUp(self):
        self.calls = []
        self._real = hp._nft_apply_json
        hp._nft_apply_json = lambda doc: (self.calls.append(doc), (0, ""))[1]
        hp._timer = None
        hp._backup = hp._NO_BACKUP
        hp._nft_rollback_owed = None

    def tearDown(self):
        hp._nft_apply_json = self._real
        hp._timer = None
        hp._backup = hp._NO_BACKUP
        hp._nft_rollback_owed = None

    def test_restoring_nothing_touches_the_kernel_not_at_all(self):
        ok, detail = hp._restore(hp._NO_BACKUP)
        self.assertTrue(ok)
        self.assertEqual(self.calls, [], "restore must not issue any nft command")
        self.assertIn("nothing to restore", detail)

    def test_restoring_an_absent_table_deletes(self):
        # Distinct from the above: we did capture state, and the state was "no table".
        ok, _ = hp._restore(None)
        self.assertTrue(ok)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("delete", self.calls[0]["nftables"][0])

    def test_restoring_a_captured_table_deletes_then_re_adds(self):
        backup = [{"table": {"family": "inet", "name": "heliopause"}}]
        ok, _ = hp._restore(backup)
        self.assertTrue(ok)
        self.assertEqual(len(self.calls), 2)
        self.assertIn("delete", self.calls[0]["nftables"][0])
        self.assertIn("add", self.calls[1]["nftables"][0])

    def test_a_second_rollback_does_not_delete_the_live_table(self):
        # The bug this pins: the first rollback consumes the backup. If the slot reset to None
        # rather than _NO_BACKUP, the second call would read "there was no table" and delete.
        hp._backup = [{"table": {"family": "inet", "name": "heliopause"}}]
        hp.rollback("first")
        first = len(self.calls)
        self.calls.clear()
        hp.rollback("second")
        self.assertEqual(self.calls, [], "a consumed backup must not authorise a delete")
        self.assertGreater(first, 0)


class TestAddressCheck(unittest.TestCase):
    """A ruleset written for another machine's address must be refused, not applied.

    Measured on a real host: a mail server rebooted, a NetworkManager profile conflict left it on a
    different address than the one its policy named, and the publish succeeded anyway. The rules
    rendered cleanly, the baseline assertions all passed — and every service rule matched traffic
    that would never arrive. Nothing anywhere reported a problem.

    Under an accepting chain policy that cost nothing. Under default-deny it is every mail port
    refused while the control plane reports the host as confirmed.

    Addresses below are RFC 5737 / RFC 1918 documentation values. `.12` stands for the address the
    policy names, `.5` for the one the host actually came up on.
    """

    def setUp(self):
        self._real = hp.local_addrs
        hp.local_addrs = lambda: ({"127.0.0.1", "10.0.101.12", "192.0.2.12"}, "")

    def tearDown(self):
        hp.local_addrs = self._real

    def test_no_expectation_is_not_a_failure(self):
        # A host whose policy targets no single address — broadcast-only DHCP rules, say — has
        # nothing to check, and that must not read as a failed check.
        self.assertEqual(hp.wrong_addresses([]), ([], ""))

    def test_any_match_is_enough(self):
        # A host legitimately holds several addresses and a generation may name only one. Requiring
        # all of them would refuse correct rulesets.
        self.assertEqual(hp.wrong_addresses(["10.0.101.12"])[0], [])
        self.assertEqual(hp.wrong_addresses(["192.0.2.12", "10.0.101.12"])[0], [])

    def test_an_address_this_host_does_not_hold_is_refused(self):
        bad, _ = hp.wrong_addresses(["10.0.0.5"])
        self.assertEqual(bad, ["10.0.0.5"], "the exact failure measured on a real host")

    def test_being_unable_to_read_our_interfaces_is_a_refusal(self):
        # Not waved through. This asks whether the artifact is for us at all, and answering
        # "probably" is how the measured failure got as far as it did.
        hp.local_addrs = lambda: (None, "cannot run ip addr")
        bad, detail = hp.wrong_addresses(["10.0.101.12"])
        self.assertIsNone(bad)
        self.assertIn("ip addr", detail)

    def test_apply_refuses_before_touching_the_kernel(self):
        # The whole point of checking here rather than after applying: a wrong-address ruleset would
        # confirm cleanly, because the relay stays reachable through the baseline. The rollback timer
        # never fires, so there is nothing to undo it.
        calls = []
        real_nft = hp._nft_apply_json
        hp._nft_apply_json = lambda doc: (calls.append(doc), (0, ""))[1]
        try:
            ok, state, detail = hp.apply_artifact({
                "generation": "g", "ruleset": VALID, "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
                "expectAddrs": ["10.0.0.5"],
            })
        finally:
            hp._nft_apply_json = real_nft
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("does not hold", detail)
        self.assertEqual(calls, [], "nothing may reach the kernel")


class TestRestartWhilePending(unittest.TestCase):
    """A restart must not be able to strand a host behind a ruleset that locked it out.

    The rollback timer lives in the process. Under `nohup` — how this was first proven on real
    hosts — that was sufficient, because nothing restarted the process. Under systemd with
    `Restart=always` it is not: if the process dies between applying a locking ruleset and the
    timer firing, the timer and the backup go with it, every subsequent heartbeat fails on the
    severed path, and the code that would notice never runs. The host stays locked out forever
    holding `pending` on disk.

    So these tests are about the disk, not the timer. Each one starts a "new process" by calling
    `recover_commitment()` against a state file a previous one left behind.
    """

    def setUp(self):
        self.calls = []
        self._real = hp._nft_apply_json
        hp._nft_apply_json = lambda doc: (self.calls.append(doc), (0, ""))[1]
        hp._timer = None
        hp._backup = hp._NO_BACKUP
        hp._nft_rollback_owed = None

    def tearDown(self):
        if hp._timer is not None:
            hp._timer.cancel()
        hp._nft_apply_json = self._real
        hp._timer = None
        hp._backup = hp._NO_BACKUP
        hp._nft_rollback_owed = None
        hp.save_state(dict(hp._EMPTY_STATE))

    def _left_behind(self, **over):
        st = dict(hp._EMPTY_STATE)
        st.update({"generation": "gen-lock", "state": "pending"})
        st.update(over)
        hp.save_state(st)

    TABLE = [{"table": {"family": "inet", "name": "heliopause"}}]

    def test_an_expired_deadline_rolls_back_at_once(self):
        # The process was down longer than the confirm window. The deadline is already owed, so it
        # is honoured now rather than waited on again.
        self._left_behind(pendingBackup={"elements": self.TABLE}, rollbackAt=time.time() - 30)
        hp.recover_commitment()
        self.assertGreater(len(self.calls), 0, "an owed rollback must reach the kernel")
        self.assertEqual(hp.load_state()["state"], "rolled-back")

    def test_a_prepared_apply_is_never_confirmed_after_restart(self):
        self._left_behind(
            state="prepared",
            pendingBackup={"elements": self.TABLE},
            rollbackAt=time.time() + 300,
        )
        hp.recover_commitment()
        self.assertGreater(len(self.calls), 0, "prepared has unknown side effects and must restore now")
        self.assertEqual(hp.load_state()["state"], "rolled-back")
        self.assertIsNone(hp._timer)

    def test_a_transient_restore_failure_preserves_the_backup_for_retry(self):
        hp._nft_apply_json = lambda document: (self.calls.append(document), (1, "busy"))[1]
        self._left_behind(
            pendingBackup={"elements": self.TABLE}, rollbackAt=time.time() - 1
        )
        hp.recover_commitment()
        saved = hp.load_state()
        self.assertEqual(saved["state"], "rollback-failed")
        self.assertEqual(saved["pendingBackup"], {"elements": self.TABLE})
        self.assertIsNotNone(hp._timer, "a transient restore failure must be retried")

    def test_a_stale_same_generation_timer_cannot_consume_a_new_commitment(self):
        """Re-applying after reboot keeps the generation id but creates a new deadline/timer."""
        old_deadline = time.time() - 1
        new_deadline = time.time() + 90
        new_timer = hp.threading.Timer(90, lambda: None)
        new_backup = [{"table": {"family": "inet", "name": "heliopause"}}]
        hp.save_state({
            **hp._EMPTY_STATE,
            "generation": "g-same",
            "state": "pending",
            "pendingBackup": {"elements": new_backup},
            "rollbackAt": new_deadline,
        })
        hp._timer = new_timer
        hp._backup = new_backup

        self.assertFalse(
            hp.rollback_generation("stale callback", "g-same", "host", old_deadline)
        )
        self.assertIs(hp._timer, new_timer)
        self.assertIs(hp._backup, new_backup)
        self.assertEqual(self.calls, [])

    def test_failed_rollback_state_save_cannot_be_heartbeat_confirmed(self):
        deadline = time.time() + 90
        st = {
            **hp._EMPTY_STATE,
            "generation": "g-save-fail",
            "state": "pending",
            "referenceHash": "sha256:" + "1" * 64,
            "pendingBackup": {"elements": self.TABLE},
            "rollbackAt": deadline,
        }
        hp.save_state(st)
        hp._backup = self.TABLE
        hp._timer = hp.threading.Timer(90, lambda: None)
        hp._timer.start()
        real_save = hp._save_state_unlocked
        hp._save_state_unlocked = lambda fresh: (
            False if fresh.get("state") == "rolled-back" else real_save(fresh)
        )
        try:
            self.assertFalse(hp.rollback("injected state write failure", "g-save-fail"))
        finally:
            hp._save_state_unlocked = real_save
        self.assertEqual(hp.load_state()["state"], "pending")
        self.assertFalse(hp.confirm(hp.load_state()))
        self.assertEqual(hp._nft_rollback_owed, "g-save-fail")

    def test_a_live_deadline_re_arms_for_the_time_that_remains(self):
        # Still inside the window: the apply may yet confirm, so reverting now would undo a
        # generation that was about to succeed. Re-arm for the remainder only.
        self._left_behind(pendingBackup={"elements": self.TABLE}, rollbackAt=time.time() + 30)
        hp.recover_commitment()
        self.assertEqual(self.calls, [], "a deadline that has not passed must not fire early")
        self.assertIsNotNone(hp._timer, "the rollback must be re-armed")

    def test_the_deadline_is_absolute_so_a_crash_loop_cannot_postpone_it(self):
        # The bug behind storing a *remaining* duration: every start would reset the clock, and a
        # process crashing inside the window would push the deadline back forever while the host
        # stayed unreachable. Two recoveries in a row must converge on firing, not reset.
        self._left_behind(pendingBackup={"elements": self.TABLE}, rollbackAt=time.time() + 0.4)
        hp.recover_commitment()
        hp._timer.cancel()  # the process "dies" again before the timer fires
        hp._timer = None
        time.sleep(0.5)
        hp.recover_commitment()
        self.assertGreater(len(self.calls), 0, "the second start must honour the original deadline")

    def test_a_pending_apply_with_no_recorded_backup_removes_our_table(self):
        # Written by an agent older than this mechanism, or one that lost the field. All that is
        # known is that an unconfirmed ruleset is live. Deleting our own table returns the host to
        # what it was before heliopause touched it, which is reachable — and reachable is the goal.
        self._left_behind()
        hp.recover_commitment()
        self.assertEqual(len(self.calls), 1)
        self.assertIn("delete", self.calls[0]["nftables"][0])
        self.assertEqual(hp.load_state()["state"], "rolled-back")

    def test_a_confirmed_state_is_left_alone(self):
        # The overwhelmingly common restart: a settled host. Touching the ruleset here would mean
        # every agent upgrade flaps the firewall.
        hp.save_state({**hp._EMPTY_STATE, "generation": "gen-ok", "state": "confirmed"})
        hp.recover_commitment()
        self.assertEqual(self.calls, [])
        self.assertIsNone(hp._timer)
        self.assertEqual(hp.load_state()["state"], "confirmed")

    def test_the_commitment_survives_the_write_that_records_the_apply(self):
        """The reply handler must not write back a state copy loaded before the apply.

        Found on a real host, and only by looking: right after applying, the state file read
        `"state": "pending"` with `pendingBackup: null, rollbackAt: null` — armed in memory,
        unprotected on disk. Nothing failed, because the in-process timer still worked. The damage
        only appears if the process then dies inside the confirm window, which is precisely the
        case the on-disk commitment exists for.

        `handle_reply` loads state, calls `apply_artifact` (which persists the commitment to the
        same file), then writes its own four fields back. If it writes the copy it loaded first,
        the commitment is erased.
        """
        applied = {}

        def fake_apply(artifact, validated=None):
            # Stand in for the real apply: it persists a commitment as its side effect.
            hp._persist_commitment([{"table": {"family": "inet", "name": "heliopause"}}],
                                   time.time() + 60)
            applied["yes"] = True
            return True, "pending", ""

        real_apply, real_fetch = hp.apply_artifact, hp.fetch_artifact
        hp.apply_artifact = fake_apply
        hp.fetch_artifact = lambda: {
            "generation": "g-new", "ruleset": VALID, "rulesetHash": VALID_HASH,
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
        }
        try:
            hp.save_state(dict(hp._EMPTY_STATE))
            st = hp.load_state()  # the stale copy — loaded before the apply, as the real loop does
            hp.handle_reply(st, {"schemaVersion": hp.SCHEMA_VERSION, "generation": "g-new",
                                 "gate": {"open": True}})
        finally:
            hp.apply_artifact, hp.fetch_artifact = real_apply, real_fetch

        self.assertTrue(applied.get("yes"), "the apply path did not run — test is not exercising it")
        saved = hp.load_state()
        self.assertEqual(saved["state"], "pending")
        self.assertIsNotNone(saved["pendingBackup"],
                             "the commitment was erased — a restart now would strand the host")
        self.assertIsNotNone(saved["rollbackAt"])

    def test_a_confirmed_generation_is_reapplied_when_the_table_is_gone(self):
        """A reboot destroys the table but not the state file, and the agent must notice.

        Measured on mailer-01: after `reboot` the host held only `table inet firewalld` — our table
        was gone, kernel memory does not survive — while /var/lib/.../state.json still read
        `"state": "confirmed"`. The agent read "already applied" and did nothing, permanently.

        Under stage 1 that was harmless: the ruleset blocked nothing. Under default-deny the
        firewall silently ceases to exist *while the control plane reports it as present*, which is
        the worst pairing available — the thing that would warn you is the thing that is wrong.
        """
        seen = {}

        def fake_apply(artifact, validated=None):
            seen["generation"] = artifact.get("generation")
            return True, "pending", ""

        real_apply, real_fetch = hp.apply_artifact, hp.fetch_artifact
        real_report = hp._host_observation_report
        hp.apply_artifact = fake_apply
        hp.fetch_artifact = lambda: {
            "generation": "g1", "ruleset": VALID, "rulesetHash": VALID_HASH,
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
        }
        # What `nft list table` returns when the table does not exist.
        hp._host_observation_report = lambda: {
            "observed": None, "detail": "table inet heliopause is absent",
            "foreignFilters": [], "publishedPorts": [],
        }
        try:
            hp.save_state({**hp._EMPTY_STATE, "generation": "g1", "state": "confirmed",
                           "referenceHash": "sha256:old"})
            hp.handle_reply(hp.load_state(), {"schemaVersion": hp.SCHEMA_VERSION, "generation": "g1",
                                              "gate": {"open": True}})
        finally:
            hp.apply_artifact, hp.fetch_artifact = real_apply, real_fetch
            hp._host_observation_report = real_report

        self.assertEqual(seen.get("generation"), "g1",
                         "a confirmed generation whose table has vanished must be re-applied")

    def test_a_confirmed_generation_still_present_is_left_alone(self):
        """The common case, and the one the fix must not break.

        If this re-applied on every beat the firewall would be rewritten every interval forever —
        which is the failure the `confirmed` short-circuit exists to prevent.
        """
        calls = []
        real_apply, real_fetch = hp.apply_artifact, hp.fetch_artifact
        real_report = hp._host_observation_report
        hp.apply_artifact = lambda a, validated=None: (calls.append(a), (True, "pending", ""))[1]
        hp.fetch_artifact = lambda: {
            "generation": "g1", "ruleset": VALID, "rulesetHash": VALID_HASH,
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
        }
        hp._host_observation_report = lambda: {
            "observed": "sha256:present", "detail": "",
            "foreignFilters": [], "publishedPorts": [],
        }
        try:
            hp.save_state({**hp._EMPTY_STATE, "generation": "g1", "state": "confirmed"})
            hp.handle_reply(hp.load_state(), {"schemaVersion": hp.SCHEMA_VERSION, "generation": "g1",
                                              "gate": {"open": True}})
        finally:
            hp.apply_artifact, hp.fetch_artifact = real_apply, real_fetch
            hp._host_observation_report = real_report
        self.assertEqual(calls, [], "a table that is present must not be re-applied")

    def test_confirming_spends_the_commitment(self):
        # Otherwise the next restart would find a stale commitment and revert a generation that
        # had already been confirmed and running for weeks.
        st = {**hp._EMPTY_STATE, "generation": "g", "state": "pending",
              "pendingBackup": {"elements": self.TABLE}, "rollbackAt": time.time() + 60,
              "referenceHash": "sha256:" + "1" * 64}
        hp.save_state(st)
        hp._timer = hp.threading.Timer(60, lambda: None)
        hp._timer.start()
        hp.confirm(st)
        saved = hp.load_state()
        self.assertIsNone(saved["pendingBackup"])
        self.assertIsNone(saved["rollbackAt"])

    def test_kernel_apply_observes_a_durable_pending_state(self):
        """Crash immediately inside nft apply: recovery must already see a pending promise."""
        seen = {"pending": False}
        real_snapshot = hp.snapshot
        real_missing = hp.missing_assertions
        hp.snapshot = lambda: ([], [], "")
        hp.missing_assertions = lambda _required: ([], "")

        def kernel_apply(_doc):
            saved = hp.load_state()
            self.assertEqual(saved["state"], "prepared")
            self.assertEqual(saved["generation"], "g-crash-window")
            self.assertIsNotNone(saved["pendingBackup"])
            self.assertIsNotNone(saved["rollbackAt"])
            seen["pending"] = True
            return 0, ""

        hp._nft_apply_json = kernel_apply
        try:
            ok, state, _ = hp.apply_artifact({
                "generation": "g-crash-window",
                "ruleset": VALID,
                "rulesetHash": "sha256:" + hp.hashlib.sha256(VALID.encode()).hexdigest(),
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            })
        finally:
            hp.snapshot = real_snapshot
            hp.missing_assertions = real_missing
        self.assertTrue(ok)
        self.assertEqual(state, "pending")
        self.assertTrue(seen["pending"])

    def test_post_apply_hash_does_not_reuse_the_previous_generation_cache(self):
        real_snapshot = hp.snapshot
        snapshots = iter((([], [], ""), ([{"table": TABLE}], [], "")))
        hp.snapshot = lambda: next(snapshots)
        hp._nft_apply_json = lambda _doc: (0, "")
        with hp._host_observe_lock:
            hp._host_observe_value = {
                "observed": "sha256:" + "0" * 64,
                "detail": "", "foreignFilters": [], "publishedPorts": [],
            }
            hp._host_observe_at = time.monotonic()
        try:
            ok, _, _ = hp.apply_artifact({
                "generation": "g-new-baseline", "ruleset": VALID,
                "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            })
            self.assertTrue(ok)
            expected = hp._observed_digest([{"table": TABLE}])
            pending = hp.load_state()
            self.assertEqual(pending["referenceHash"], expected)
            self.assertTrue(hp.confirm(pending))
            self.assertEqual(hp.load_state()["referenceHash"], expected)
        finally:
            hp.snapshot = real_snapshot

    def test_timer_restore_cannot_finish_before_a_late_kernel_commit(self):
        real_snapshot = hp.snapshot
        entered = hp.threading.Event()
        release = hp.threading.Event()
        restore_started = hp.threading.Event()
        calls = []
        first = {"yes": True}

        def kernel(document):
            if first["yes"]:
                first["yes"] = False
                entered.set()
                release.wait(1)
                calls.append("apply")
                return 0, ""
            restore_started.set()
            calls.append("restore")
            return 0, ""

        hp.snapshot = lambda: ([], [], "") if first["yes"] else ([{"table": TABLE}], [], "")
        hp._nft_apply_json = kernel
        result = []
        apply_thread = hp.threading.Thread(target=lambda: result.append(hp.apply_artifact({
            "generation": "g-serial", "ruleset": VALID, "rulesetHash": VALID_HASH,
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
        })))
        rollback_thread = hp.threading.Thread(
            target=lambda: hp.rollback_generation("injected timer", "g-serial")
        )
        try:
            apply_thread.start()
            self.assertTrue(entered.wait(1))
            rollback_thread.start()
            time.sleep(0.05)
            self.assertFalse(
                restore_started.is_set(),
                "restore must wait for the bounded kernel transaction to finish",
            )
            release.set()
            apply_thread.join(2)
            rollback_thread.join(2)
        finally:
            release.set()
            hp.snapshot = real_snapshot
        self.assertFalse(apply_thread.is_alive())
        self.assertFalse(rollback_thread.is_alive())
        self.assertEqual(calls[0], "apply")
        self.assertIn("restore", calls[1:])
        self.assertEqual(hp.load_state()["state"], "rolled-back")

    def test_absolute_deadline_is_not_restarted_after_a_slow_kernel_apply(self):
        real_snapshot = hp.snapshot
        real_time = hp.time
        now = {"value": 1_000.0}

        class Clock:
            def time(self):
                return now["value"]

            def __getattr__(self, name):
                return getattr(real_time, name)

        calls = {"apply": 0}

        def kernel(_document):
            calls["apply"] += 1
            if calls["apply"] == 1:
                now["value"] += hp.NFT_CONFIRM_MIN_SEC + 1
            return 0, ""

        hp.time = Clock()
        hp.snapshot = lambda: ([], [], "")
        hp._nft_apply_json = kernel
        try:
            ok, state, detail = hp.apply_artifact({
                "generation": "g-deadline", "ruleset": VALID, "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            })
        finally:
            hp.time = real_time
            hp.snapshot = real_snapshot
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("deadline elapsed", detail)

    def test_confirmation_save_failure_keeps_the_timer_and_backup_live(self):
        st = {
            **hp._EMPTY_STATE, "generation": "g-save-fail", "state": "pending",
            "referenceHash": "sha256:" + "1" * 64,
            "pendingBackup": {"elements": self.TABLE}, "rollbackAt": time.time() + 60,
        }
        hp.save_state(st)
        hp._backup = self.TABLE
        hp._timer = hp.threading.Timer(60, lambda: None)
        hp._timer.start()
        real_save = hp._save_state_unlocked
        hp._save_state_unlocked = lambda fresh: (
            False if fresh.get("state") == "confirmed" else real_save(fresh)
        )
        try:
            self.assertFalse(hp.confirm(st))
        finally:
            hp._save_state_unlocked = real_save
        self.assertIsNotNone(hp._timer)
        self.assertEqual(hp.load_state()["state"], "pending")
        self.assertEqual(hp._backup, self.TABLE)

    def test_invalid_timeout_is_refused_before_kernel_apply(self):
        calls = []
        real_snapshot = hp.snapshot
        hp.snapshot = lambda: ([], [], "")
        hp._nft_apply_json = lambda doc: (calls.append(doc), (0, ""))[1]
        try:
            ok, state, detail = hp.apply_artifact({
                "generation": "g-bad-timeout", "ruleset": VALID, "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": "sixty",
            })
        finally:
            hp.snapshot = real_snapshot
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("integer", detail)
        self.assertEqual(calls, [])

    def test_non_finite_timeout_is_a_refusal_not_a_parser_exception(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            parsed, reason = hp._parse_timeout(
                value, hp.NFT_CONFIRM_MIN_SEC, hp.NFT_CONFIRM_MIN_SEC,
                hp.NFT_CONFIRM_MAX_SEC, "confirmTimeoutSec",
            )
            self.assertIsNone(parsed)
            self.assertIn("integer", reason)

    def test_non_text_generation_is_refused_before_kernel_apply(self):
        calls = []
        real_snapshot = hp.snapshot
        hp.snapshot = lambda: (calls.append("snapshot"), ([], [], ""))[1]
        try:
            ok, state, detail = hp.apply_artifact({
                "generation": {"hostile": True},
                "ruleset": VALID,
                "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            })
        finally:
            hp.snapshot = real_snapshot
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("generation", detail)
        self.assertEqual(calls, [])

    def test_timeout_shorter_than_a_safe_heartbeat_window_is_refused(self):
        calls = []
        real_snapshot = hp.snapshot
        hp.snapshot = lambda: ([], [], "")
        hp._nft_apply_json = lambda doc: (calls.append(doc), (0, ""))[1]
        try:
            ok, state, detail = hp.apply_artifact({
                "generation": "g-too-fast", "ruleset": VALID,
                "rulesetHash": VALID_HASH,
                "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC - 1,
            })
        finally:
            hp.snapshot = real_snapshot
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("between", detail)
        self.assertEqual(calls, [])

    def test_missing_timeout_uses_the_receiver_safety_floor(self):
        doc, timeout, detail = hp._preflight_host_artifact({
            "generation": "g-default", "ruleset": VALID, "rulesetHash": VALID_HASH,
        })
        self.assertIsNotNone(doc, detail)
        self.assertEqual(timeout, hp.NFT_CONFIRM_MIN_SEC)

    def test_safe_reply_wrapper_contains_malformed_reply_failures(self):
        self.assertFalse(hp.handle_reply_safely(hp.load_state(), ["not", "an", "object"]))

    def test_concurrent_nft_and_workload_promises_preserve_both_halves(self):
        """The two timer threads must not win a last-writer-wins race on one state file."""
        entered = hp.threading.Event()
        release = hp.threading.Event()
        results = []
        real_save = hp._save_state_unlocked
        first = {"yes": True}

        def paused_save(st):
            if first["yes"]:
                first["yes"] = False
                entered.set()
                release.wait(1)
            return real_save(st)

        hp._save_state_unlocked = paused_save
        record = {"ref": "util/hp-dev-p700", "uid": None, "cluster": "dev",
                  "generation": "g-both", "previous": None}
        try:
            nft = hp.threading.Thread(target=lambda: results.append(
                hp._persist_commitment([], time.time() + 60, "g-both", "sha256:nft")
            ))
            workload = hp.threading.Thread(target=lambda: results.append(
                hp._wl_persist([record], time.time() + 300, "g-both")
            ))
            nft.start()
            self.assertTrue(entered.wait(1), "first state transaction never reached its write")
            workload.start()
            release.set()
            nft.join(2)
            workload.join(2)
        finally:
            release.set()
            hp._save_state_unlocked = real_save
        self.assertEqual(results, [True, True])
        saved = hp.load_state()
        self.assertEqual(saved["state"], "prepared")
        self.assertEqual(saved["workloadState"], "prepared")
        self.assertIsNotNone(saved["pendingBackup"])
        self.assertEqual(hp._workload_refs(saved["workloadApplied"]), ["util/hp-dev-p700"])


def cnp(name="hp-dev-p700", namespace="util"):
    policy_id = name.removeprefix("hp-dev-").removesuffix("-ingress")
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"managed-by": "heliopause", "heliopause.io/cluster": "dev"},
            "annotations": {
                "heliopause.io/policy-id": policy_id,
                "heliopause.io/applier": hp.HOST_ID,
                "heliopause.io/generation": "g1",
            },
        },
        "spec": {
            "description": f"{policy_id} test",
            "endpointSelector": {"matchLabels": {hp.NS_LABEL: namespace, "app": "zot"}},
            "enableDefaultDeny": {"ingress": True},
            "ingress": [{"fromEntities": ["all"]}],
        },
    }


def wl(*objects):
    """Serialise objects the way the renderer does — a `v1/List`, which `kubectl apply -f` accepts.

    A bare JSON array is rejected by kubectl before reaching the API server, so the wrapper is part of
    the contract rather than packaging. Measured against the live cluster.
    """
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": list(objects)})


def validate_wl(text):
    return hp.validate_workload(text, cluster="dev", applier=hp.HOST_ID, generation="g1")


def baseline(namespace="util"):
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "hp-dev-posture-baseline", "namespace": namespace,
            "labels": {"managed-by": "heliopause", "heliopause.io/cluster": "dev"},
            "annotations": {"heliopause.io/policy-id": "posture", "heliopause.io/applier": hp.HOST_ID,
                            "heliopause.io/generation": "g1", "heliopause.io/policy-kind": "namespace-ingress-default-deny"},
        },
        "spec": {"description": "namespace default deny", "endpointSelector": {"matchLabels": {hp.NS_LABEL: namespace}},
                 "enableDefaultDeny": {"ingress": True},
                 "ingress": [{"fromEndpoints": [{"matchLabels": {hp.NS_LABEL: hp.BASELINE_NEVER_NAMESPACE}}]}]},
    }


def egress_baseline(namespace="util", selector=None, policy_id="broker"):
    """The posture object that closes one label selector's egress, as the renderer emits it."""
    labels = selector if selector is not None else {hp.NS_LABEL: namespace, "app": "vultr-broker"}
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": f"hp-dev-{policy_id}-egress-baseline", "namespace": namespace,
            "labels": {"managed-by": "heliopause", "heliopause.io/cluster": "dev"},
            "annotations": {"heliopause.io/policy-id": policy_id, "heliopause.io/applier": hp.HOST_ID,
                            "heliopause.io/generation": "g1",
                            "heliopause.io/policy-kind": "selector-egress-default-deny"},
        },
        "spec": {"description": "broker default deny egress",
                 "endpointSelector": {"matchLabels": labels},
                 "enableDefaultDeny": {"egress": True},
                 "egress": [{"toEndpoints": [{"matchLabels": {hp.NS_LABEL: hp.BASELINE_NEVER_NAMESPACE}}]}]},
    }


class TestCrossLayerOrdering(unittest.TestCase):
    def setUp(self):
        hp.save_state(dict(hp._EMPTY_STATE))
        self.real_fetch = hp.fetch_artifact
        self.real_workload = hp.apply_workload
        self.real_host = hp.apply_artifact
        self.real_rollback_generation = hp.rollback_generation

    def tearDown(self):
        hp.fetch_artifact = self.real_fetch
        hp.apply_workload = self.real_workload
        hp.apply_artifact = self.real_host
        hp.rollback_generation = self.real_rollback_generation
        if hp._wl_timer is not None:
            hp._wl_timer.cancel()
        hp._wl_timer = None
        hp._wl_rollback_owed = None
        hp._nft_rollback_owed = None
        hp.save_state(dict(hp._EMPTY_STATE))

    @staticmethod
    def artifact():
        return {
            "generation": "g-order", "ruleset": VALID, "rulesetHash": VALID_HASH,
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            "workload": {"applier": hp.HOST_ID},
        }

    def test_workload_side_effect_precedes_the_short_host_timer(self):
        order = []
        hp.fetch_artifact = self.artifact
        hp.apply_workload = lambda _artifact: (
            order.append("workload"), (True, "pending", "")
        )[1]
        hp.apply_artifact = lambda _artifact, validated=None: (
            order.append("host"), (True, "pending", "")
        )[1]
        hp.handle_reply(hp.load_state(), {
            "schemaVersion": hp.SCHEMA_VERSION,
            "generation": "g-order", "gate": {"open": True},
        })
        self.assertEqual(order, ["workload", "host"])

    def test_workload_failure_leaves_the_host_kernel_untouched(self):
        host_calls = []
        hp.fetch_artifact = self.artifact
        hp.apply_workload = lambda _artifact: (False, "rolled-back", "API refused")
        hp.apply_artifact = lambda _artifact, validated=None: (
            host_calls.append(validated), (True, "pending", "")
        )[1]
        hp.handle_reply(hp.load_state(), {
            "schemaVersion": hp.SCHEMA_VERSION,
            "generation": "g-order", "gate": {"open": True},
        })
        self.assertEqual(host_calls, [])

    def test_host_failure_rolls_back_the_same_generation_workload(self):
        hp.fetch_artifact = self.artifact

        def workload(_artifact):
            hp.update_state(lambda st: st.update({
                "workloadState": "pending",
                "workloadGeneration": "g-order",
                "workloadApplied": [],
                "workloadRollbackAt": time.time() + 300,
            }))
            return True, "pending", ""

        hp.apply_workload = workload
        hp.apply_artifact = lambda _artifact, validated=None: (
            False, "rolled-back", "host verification failed"
        )
        hp.handle_reply(hp.load_state(), {
            "schemaVersion": hp.SCHEMA_VERSION,
            "generation": "g-order", "gate": {"open": True},
        })
        saved = hp.load_state()
        self.assertEqual(saved["workloadGeneration"], "g-order")
        self.assertEqual(saved["workloadState"], "rolled-back")
        self.assertIn("host verification failed", saved["workloadDetail"])

    def test_result_recording_cannot_strand_an_nft_rollback_whose_save_failed(self):
        hp.fetch_artifact = self.artifact
        hp.apply_workload = lambda _artifact: (True, None, "")
        hp.rollback_generation = lambda *_args: False

        def host(_artifact, validated=None):
            hp.update_state(lambda st: st.update({
                "generation": "g-order", "state": "pending",
                "pendingBackup": {"elements": []},
                "rollbackAt": time.time() + 90,
            }))
            hp._nft_rollback_owed = "g-order"
            return False, "rolled-back", "rollback result fsync failed"

        hp.apply_artifact = host
        hp.handle_reply(hp.load_state(), {
            "schemaVersion": hp.SCHEMA_VERSION,
            "generation": "g-order", "gate": {"open": True},
        })
        saved = hp.load_state()
        self.assertEqual(saved["state"], "pending")
        self.assertIsNotNone(saved["pendingBackup"])

    def test_result_recording_cannot_strand_a_workload_rollback_whose_save_failed(self):
        hp.fetch_artifact = self.artifact
        hp.rollback_generation = lambda *_args: False

        def workload(_artifact):
            hp.update_state(lambda st: st.update({
                "workloadState": "pending",
                "workloadGeneration": "g-order",
                "workloadApplied": [],
                "workloadRollbackAt": time.time() + 300,
            }))
            hp._wl_rollback_owed = "g-order"
            return False, "rolled-back", "rollback result fsync failed"

        hp.apply_workload = workload
        hp.handle_reply(hp.load_state(), {
            "schemaVersion": hp.SCHEMA_VERSION,
            "generation": "g-order", "gate": {"open": True},
        })
        saved = hp.load_state()
        self.assertEqual(saved["workloadState"], "pending")
        self.assertIsNotNone(saved["workloadRollbackAt"])


class TestWorkloadValidation(unittest.TestCase):
    def test_accepts_an_exact_namespace_ingress_default_deny_baseline(self):
        objects, reason = validate_wl(wl(baseline()))
        self.assertEqual(reason, "")
        self.assertEqual(objects[0]["metadata"]["name"], "hp-dev-posture-baseline")

    def test_refuses_a_baseline_with_an_allow_rule(self):
        obj = baseline()
        obj["spec"]["ingress"] = [{"fromEntities": ["all"]}]
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("exact unmatchable source rule", reason)

    def test_accepts_a_peer_in_a_namespace_it_may_look_at_but_not_write_to(self):
        # The egress allow every closed posture needs. The object lands in a writable namespace; the
        # peer it names is CoreDNS, where this applier holds no CiliumNetworkPolicy verbs — and must
        # not, because an object there could close CoreDNS. Only the pod list is required, and only
        # so the enforcement gate can see the pods before confirming.
        obj = cnp()
        obj["spec"] = {
            "description": "p700 test",
            "endpointSelector": {"matchLabels": {hp.NS_LABEL: "util", "app": "zot"}},
            "enableDefaultDeny": {"egress": False},
            "egress": [{
                "toEndpoints": [{"matchLabels": {hp.NS_LABEL: "kube-system", "k8s-app": "kube-dns"}}],
                "toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}]}],
            }],
        }
        doc, reason = validate_wl(wl(obj))
        self.assertIsNone(doc)
        self.assertIn("HELIOPAUSE_K8S_PEER_NAMESPACES", reason)

        real = hp.WORKLOAD_PEER_NAMESPACES
        hp.WORKLOAD_PEER_NAMESPACES = real | {"kube-system"}
        try:
            doc, reason = validate_wl(wl(obj))
            self.assertIsNotNone(doc, reason)
            # Widening the peer set must not widen where objects may land.
            refused, why = validate_wl(wl(cnp(namespace="kube-system")))
            self.assertIsNone(refused)
            self.assertIn("HELIOPAUSE_K8S_NAMESPACES", why)
        finally:
            hp.WORKLOAD_PEER_NAMESPACES = real

    def test_accepts_an_exact_selector_egress_default_deny_baseline(self):
        objects, reason = validate_wl(wl(egress_baseline()))
        self.assertEqual(reason, "")
        self.assertEqual(objects[0]["metadata"]["name"], "hp-dev-broker-egress-baseline")

    def test_refuses_an_egress_baseline_that_closes_a_whole_namespace(self):
        # An `endpointSelector` holding nothing but the namespace closes every pod in it. Both
        # workloads this object exists for share a namespace with pods nobody asked to contain, so
        # the difference between "the broker" and "everything beside the broker" is an outage — and
        # the object applies cleanly either way.
        objects, reason = validate_wl(wl(egress_baseline(selector={hp.NS_LABEL: "util"})))
        self.assertIsNone(objects)
        self.assertIn("names no label besides its namespace", reason)

    def test_refuses_an_egress_baseline_that_does_not_close_anything(self):
        # `enableDefaultDeny: {egress: false}` on this object would leave the endpoint's posture
        # exactly where it was while the object still reads, in a diff, as containment.
        obj = egress_baseline()
        obj["spec"]["enableDefaultDeny"] = {"egress": False}
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("enableDefaultDeny must be egress true", reason)

    def test_refuses_an_egress_baseline_whose_rule_lets_anything_out(self):
        # The rule has to exist — Cilium's `Sanitize()` enters egress default-deny only when an
        # egress section is present — and it has to be unmatchable. `[{}]` satisfies the first and
        # inverts the second: every peer allowed, under an object named for closing.
        obj = egress_baseline()
        obj["spec"]["egress"] = [{}]
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("exact unmatchable destination rule", reason)

    def test_refuses_an_egress_baseline_carrying_another_direction(self):
        obj = egress_baseline()
        obj["spec"]["ingress"] = [{"fromEntities": ["all"]}]
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("unsupported traffic direction", reason)

    def test_refuses_an_egress_baseline_under_the_ingress_baseline_name(self):
        # The two suffixes are what let one workload carry both postures without the second
        # overwriting the first at apply, so the name has to follow the kind.
        obj = egress_baseline()
        obj["metadata"]["name"] = "hp-dev-broker-baseline"
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("is not derived from cluster and policy-id", reason)

    def test_refuses_an_unknown_policy_kind_instead_of_reading_it_as_a_flow(self):
        # Falling through to the traffic-flow rules would check the wrong template against it, and a
        # posture object shaped like an allow could pass.
        obj = egress_baseline()
        obj["metadata"]["annotations"]["heliopause.io/policy-kind"] = "selector-egress-allow"
        objects, reason = validate_wl(wl(obj))
        self.assertIsNone(objects)
        self.assertIn("unsupported heliopause.io/policy-kind", reason)
    """The workload document reaches Kubernetes mutation commands, which accept privileged kinds too.

    So the allowlist here is doing the same job as the nftables one: an artifact that got this far
    unchecked could create a ClusterRoleBinding as easily as a network policy. The difference from the
    nftables side is that there is no second layer behind a pod destination (evaluation rule 8), so a
    refusal has to be loud rather than a quiet skip.
    """

    def test_accepts_a_real_document(self):
        doc, reason = validate_wl(wl(cnp()))
        self.assertIsNotNone(doc, reason)
        self.assertEqual(hp.workload_objects(doc), ["util/hp-dev-p700"])

    def test_refuses_a_bare_object(self):
        # A single CNP with no List wrapper. `mustExist` would then look for objects in a shape the
        # renderer never emits.
        self.assertIsNone(validate_wl(json.dumps(cnp()))[0])

    def test_refuses_a_bare_array(self):
        # The shape the renderer emitted before it was corrected. kubectl rejects it outright, so an
        # agent that accepted it would apply nothing while reporting success — the failure this whole
        # layer exists to remove.
        self.assertIsNone(validate_wl(json.dumps([cnp()]))[0])

    def test_refuses_a_list_of_the_wrong_api_version(self):
        # `kind: List` under some other group is not the core List kubectl dispatches on.
        doc, reason = validate_wl(
            json.dumps({"apiVersion": "apps/v1", "kind": "List", "items": [cnp()]})
        )
        self.assertIsNone(doc)
        self.assertIn("expected v1/List", reason)

    def test_refuses_a_list_with_no_items(self):
        doc, reason = validate_wl(json.dumps({"apiVersion": "v1", "kind": "List"}))
        self.assertIsNone(doc)
        self.assertIn("missing", reason)

    def test_refuses_another_kind(self):
        evil = {**cnp(), "kind": "ClusterRoleBinding"}
        doc, reason = validate_wl(wl(evil))
        self.assertIsNone(doc)
        self.assertIn("CiliumNetworkPolicy", reason)

    def test_refuses_another_api_group(self):
        evil = {**cnp(), "apiVersion": "rbac.authorization.k8s.io/v1"}
        self.assertIsNone(validate_wl(wl(evil))[0])

    def test_refuses_an_object_with_no_namespace(self):
        # Without both name and namespace, `mustExist` cannot name it — so it could be applied and
        # then never verified, which is the failure this whole layer exists to remove.
        bad = {**cnp(), "metadata": {"name": "x"}}
        doc, reason = validate_wl(wl(bad))
        self.assertIsNone(doc)
        self.assertIn("namespace", reason)

    def test_refuses_a_smuggled_object_after_a_valid_one(self):
        # Every element is checked, not just the first.
        evil = {**cnp(name="evil"), "kind": "Secret"}
        self.assertIsNone(validate_wl(wl(cnp(), evil))[0])

    def test_refuses_unparseable_json(self):
        self.assertIsNone(validate_wl("{not json")[0])

    def test_refuses_a_namespace_outside_the_local_allowlist(self):
        doc, reason = validate_wl(wl(cnp(namespace="kube-system")))
        self.assertIsNone(doc)
        self.assertIn("HELIOPAUSE_K8S_NAMESPACES", reason)

    def test_refuses_missing_or_spoofed_ownership_metadata(self):
        unmanaged = cnp()
        unmanaged["metadata"]["labels"]["managed-by"] = "flux"
        self.assertIsNone(validate_wl(wl(unmanaged))[0])

        wrong_generation = cnp()
        wrong_generation["metadata"]["annotations"]["heliopause.io/generation"] = "g2"
        doc, reason = validate_wl(wl(wrong_generation))
        self.assertIsNone(doc)
        self.assertIn("different generation", reason)

    def test_refuses_a_name_not_derived_from_cluster_and_policy_id(self):
        bad = cnp()
        bad["metadata"]["name"] = "hp-dev-someone-elses-policy"
        doc, reason = validate_wl(wl(bad))
        self.assertIsNone(doc)
        self.assertIn("not derived", reason)

    def test_refuses_a_wildcard_or_unexpected_spec(self):
        wildcard = cnp()
        wildcard["spec"]["endpointSelector"] = {"matchLabels": {}}
        self.assertIsNone(validate_wl(wl(wildcard))[0])

        extra = cnp()
        extra["spec"]["nodeSelector"] = {}
        doc, reason = validate_wl(wl(extra))
        self.assertIsNone(doc)
        self.assertIn("unsupported", reason)

    def test_refuses_a_noncanonical_cidr_that_would_silently_widen(self):
        bad = cnp()
        bad["spec"]["ingress"] = [{"fromCIDR": ["10.0.0.1/24"]}]
        doc, reason = validate_wl(wl(bad))
        self.assertIsNone(doc)
        self.assertIn("invalid CIDR", reason)

    def test_refuses_extra_wrapper_or_object_fields(self):
        wrapped = json.loads(wl(cnp()))
        wrapped["metadata"] = {"name": "smuggled"}
        doc, reason = validate_wl(json.dumps(wrapped))
        self.assertIsNone(doc)
        self.assertIn("wrapper", reason)

        obj = cnp()
        obj["status"] = {"derivativePolicies": 1}
        doc, reason = validate_wl(wl(obj))
        self.assertIsNone(doc)
        self.assertIn("top-level", reason)

    def test_refuses_duplicate_object_references(self):
        doc, reason = validate_wl(wl(cnp(), cnp()))
        self.assertIsNone(doc)
        self.assertIn("duplicates workload object", reason)

    def test_refuses_multiple_peer_fields_in_one_rule(self):
        bad = cnp()
        bad["spec"]["ingress"] = [{"fromEntities": ["all"], "fromCIDR": ["10.0.0.0/24"]}]
        doc, reason = validate_wl(wl(bad))
        self.assertIsNone(doc)
        self.assertIn("exactly one", reason)

    def test_port_zero_is_only_the_renderer_protocol_wildcard(self):
        valid = cnp()
        valid["spec"]["ingress"] = [{
            "fromEntities": ["all"],
            "toPorts": [{"ports": [{"port": "0", "protocol": "TCP"}]}],
        }]
        self.assertIsNotNone(validate_wl(wl(valid))[0])

        for ports in (
            [{"port": "0", "protocol": "ANY"}],
            [{"port": "0", "protocol": "TCP"}, {"port": "443", "protocol": "TCP"}],
            [{"port": "0", "endPort": 65535, "protocol": "TCP"}],
        ):
            bad = cnp()
            bad["spec"]["ingress"] = [{
                "fromEntities": ["all"], "toPorts": [{"ports": ports}],
            }]
            doc, reason = validate_wl(wl(bad))
            self.assertIsNone(doc)
            self.assertIn("port 0", reason)


class TestWorkloadApply(unittest.TestCase):
    """Ownership, durable commitment, enforcement gate and identity-safe rollback."""

    def setUp(self):
        self.calls = []
        self._real = hp.kubectl
        self._real_delete = hp._delete_workload_object
        hp._wl_timer = None
        hp._wl_rollback_owed = None
        hp.save_state(dict(hp._EMPTY_STATE))
        self.host = hp.HOST_ID
        self.cluster = {}
        self.deleted = []
        self.stub()
        hp._delete_workload_object = self.delete

    def tearDown(self):
        hp.kubectl = self._real
        hp._delete_workload_object = self._real_delete
        if hp._wl_timer is not None:
            hp._wl_timer.cancel()
            hp._wl_timer = None
        hp._wl_rollback_owed = None
        hp.save_state(dict(hp._EMPTY_STATE))

    @staticmethod
    def live(obj=None, uid="uid-new", rv="1"):
        out = json.loads(json.dumps(obj or cnp()))
        out["metadata"]["uid"] = uid
        out["metadata"]["resourceVersion"] = rv
        return out

    def stub(self, override=None):
        def fake(args, stdin=None, timeout_sec=None):
            self.calls.append(args)
            if override:
                answer = override(args, stdin)
                if answer is not None:
                    return answer
            if args[0] == "create":
                obj = json.loads(stdin)
                ref = f"{obj['metadata']['namespace']}/{obj['metadata']['name']}"
                if ref in self.cluster:
                    return 1, "", "AlreadyExists"
                self.cluster[ref] = self.live(
                    obj, uid=f"uid-{len(self.cluster) + 1}", rv="2"
                )
                return 0, "", ""
            if args[0] == "replace":
                obj = json.loads(stdin)
                ref = f"{obj['metadata']['namespace']}/{obj['metadata']['name']}"
                current = self.cluster.get(ref)
                if not current or current["metadata"]["resourceVersion"] != obj["metadata"]["resourceVersion"]:
                    return 1, "", "Conflict"
                self.cluster[ref] = self.live(obj, uid=obj["metadata"]["uid"], rv="3")
                return 0, "", ""
            if "get" in args and "ciliumnetworkpolicy" in args:
                ns = args[args.index("-n") + 1]
                name = args[args.index("ciliumnetworkpolicy") + 1]
                current = self.cluster.get(f"{ns}/{name}")
                if not current:
                    return 1, "", f'ciliumnetworkpolicy "{name}" not found'
                return (0, json.dumps(current), "") if "json" in args else (0, f"ciliumnetworkpolicy/{name}\n", "")
            if "get" in args and "pods" in args:
                return 0, "pod/zot-0\n", ""
            return 0, "", ""
        hp.kubectl = fake

    def delete(self, ref, uid, resource_version, deadline=None):
        current = self.cluster.get(ref)
        if not current:
            return True, ""
        meta = current["metadata"]
        if meta["uid"] != uid or meta["resourceVersion"] != resource_version:
            return False, "precondition failed"
        self.deleted.append((ref, uid, resource_version))
        del self.cluster[ref]
        return True, ""

    def artifact(self, objects=None, **over):
        objects = objects if objects is not None else [cnp()]
        text = wl(*objects)
        half = {
            "policies": text,
            "policiesHash": "sha256:" + hp.hashlib.sha256(text.encode()).hexdigest(),
            "applier": self.host,
            "cluster": "dev",
            "mustExist": hp.workload_objects(objects),
            "confirmTimeoutSec": 300,
        }
        half.update(over)
        return {"generation": "g1", "workload": half}

    def test_nothing_assigned_is_not_a_state(self):
        # Every host but the designated applier. `None` rather than a state, so "not my job" can never
        # be read as something the manager might gate on.
        ok, state, _ = hp.apply_workload({"generation": "g1"})
        self.assertTrue(ok)
        self.assertIsNone(state)
        self.assertEqual(self.calls, [], "a host with no assignment must not run kubectl")

    def test_applies_and_arms_the_timer(self):
        ok, state, _ = hp.apply_workload(self.artifact())
        self.assertTrue(ok)
        self.assertEqual(state, "pending")
        self.assertIsNotNone(hp._wl_timer, "rollback must be armed after a successful apply")
        saved = hp.load_state()
        self.assertEqual(hp._workload_refs(saved["workloadApplied"]), ["util/hp-dev-p700"])
        self.assertEqual(saved["workloadGeneration"], "g1")
        self.assertEqual(saved["workloadHash"], self.artifact()["workload"]["policiesHash"])
        create = next(c for c in self.calls if c[0] == "create")
        self.assertIn("--validate=strict", create)
        self.assertNotIn("apply", create)

    def test_egress_baseline_applies_and_is_gated_on_the_pods_it_closes(self):
        # The gate asks about the *selected* pods, by their labels. Asking about the namespace would
        # confirm this generation on the strength of a pod the object does not select — and an egress
        # baseline that selects nobody closes nobody while reading as containment.
        obj = egress_baseline()
        ok, state, detail = hp.apply_workload(self.artifact([obj]))
        self.assertTrue(ok, detail)
        self.assertEqual(state, "pending")
        ref = "util/hp-dev-broker-egress-baseline"
        self.assertIn(ref, self.cluster)
        pod_queries = [c for c in self.calls if "pods" in c]
        self.assertEqual(len(pod_queries), 1)
        self.assertIn("app=vultr-broker", pod_queries[0])
        hp.rollback_workload("test egress baseline rollback", "g1")
        self.assertNotIn(ref, self.cluster)
        self.assertEqual(self.deleted[0][0], ref)

    def test_baseline_applies_reads_back_and_rolls_back_by_identity(self):
        obj = baseline()
        ok, state, detail = hp.apply_workload(self.artifact([obj]))
        self.assertTrue(ok, detail)
        self.assertEqual(state, "pending")
        ref = "util/hp-dev-posture-baseline"
        self.assertIn(ref, self.cluster)
        # The enforcement gate intentionally observes only the selected target namespace; its
        # unmatchable peer is not a Kubernetes namespace and must never be queried.
        pod_queries = [c for c in self.calls if "pods" in c]
        self.assertEqual(len(pod_queries), 1)
        self.assertIn("util", pod_queries[0])
        hp.rollback_workload("test baseline rollback", "g1")
        self.assertNotIn(ref, self.cluster)
        self.assertEqual(self.deleted[0][0], ref)

    def test_refuses_a_half_addressed_to_another_node(self):
        # Should be impossible — the relay serves per-host artifacts keyed by certificate CN. Checked
        # because the failure it catches is two nodes fighting over one cluster-scoped object.
        ok, state, detail = hp.apply_workload(self.artifact(applier="someone-else"))
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("addressed to", detail)
        self.assertEqual(self.calls, [])

    def test_refuses_a_digest_mismatch(self):
        ok, _, detail = hp.apply_workload(self.artifact(policiesHash="sha256:" + "0" * 64))
        self.assertFalse(ok)
        self.assertIn("does not match published", detail)
        self.assertEqual(self.calls, [])

    def test_refuses_when_the_manifest_and_document_disagree(self):
        # Applying either interpretation would leave the other side's check wrong.
        ok, _, detail = hp.apply_workload(self.artifact(mustExist=["util/something-else"]))
        self.assertFalse(ok)
        self.assertIn("refusing rather than guessing", detail)
        self.assertEqual(self.calls, [])

    def test_rolls_back_when_an_object_is_absent_after_a_clean_apply(self):
        # The case this layer exists for. kubectl exits 0 — the API server accepted the document — and
        # the object is not there. Cilium accepts a policy that selects nothing, so "accepted" is not
        # "in force".
        applied = {"yes": False}

        def handler(args, stdin):
            if args[0] in {"create", "replace"}:
                applied["yes"] = True
                return 0, "", ""
            if applied["yes"] and "get" in args and "ciliumnetworkpolicy" in args:
                return 1, "", 'ciliumnetworkpolicies.cilium.io "hp-dev-p700" not found'
            return None
        self.stub(handler)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("absent after apply", detail)
        self.assertIsNone(hp._wl_timer, "a failed apply must not leave a timer armed")

    def test_an_unreadable_cluster_rolls_back_rather_than_passing(self):
        # Distinct from NotFound: we do not know. Unknown must not satisfy a check — that is how a
        # policy governing zero pods passes as applied.
        applied = {"yes": False}

        def handler(args, stdin):
            if args[0] in {"create", "replace"}:
                applied["yes"] = True
                return 0, "", ""
            if applied["yes"] and "get" in args and "ciliumnetworkpolicy" in args:
                return 1, "", "Unable to connect to the server: dial tcp: i/o timeout"
            return None
        self.stub(handler)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("cannot verify", detail)

    def test_a_transient_read_error_is_not_reported_as_absence(self):
        # The same distinction at the level that decides it. `observed_objects` returning None is
        # "could not check"; returning [] would be "checked, holds none" and would revert healthy
        # policy on one failed API call.
        self.stub(lambda args, stdin: (1, "", "connection refused"))
        present, detail = hp.observed_objects(["util/hp-dev-p700"])
        self.assertIsNone(present)
        self.assertIn("cannot read", detail)

    def test_rollback_deletes_a_new_object_with_uid_and_resource_version_preconditions(self):
        hp.apply_workload(self.artifact())
        hp.rollback_workload("test")
        self.assertEqual(self.deleted, [("util/hp-dev-p700", "uid-1", "2")])
        self.assertNotIn("util/hp-dev-p700", self.cluster)
        st = hp.load_state()
        self.assertEqual(st["workloadState"], "rolled-back")
        self.assertIsNone(st["workloadRollbackAt"])

    def test_rollback_restores_a_prior_heliopause_object_instead_of_deleting_it(self):
        previous = cnp()
        previous["metadata"]["annotations"]["heliopause.io/generation"] = "g0"
        previous["spec"]["description"] = "prior policy"
        self.cluster["util/hp-dev-p700"] = self.live(previous, uid="uid-old", rv="1")
        self.assertTrue(hp.apply_workload(self.artifact())[0])
        self.assertEqual(self.cluster["util/hp-dev-p700"]["spec"]["description"], "p700 test")
        self.assertTrue(hp.rollback_workload("test"))
        restored = self.cluster["util/hp-dev-p700"]
        self.assertEqual(restored["metadata"]["uid"], "uid-old")
        self.assertEqual(restored["metadata"]["annotations"]["heliopause.io/generation"], "g0")
        self.assertEqual(restored["spec"]["description"], "prior policy")
        self.assertEqual(self.deleted, [])

    def test_preflight_refuses_an_external_object_without_overwriting_it(self):
        external = self.live(cnp(), uid="uid-flux", rv="9")
        external["metadata"]["labels"] = {"managed-by": "flux", "heliopause.io/cluster": "dev"}
        self.cluster["util/hp-dev-p700"] = external
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("refusing external object", detail)
        self.assertFalse(any(c[0] in {"create", "replace"} for c in self.calls))
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-flux")

    def test_preflight_refuses_an_object_owned_by_another_applier(self):
        external = self.live(cnp(), uid="uid-other-agent", rv="9")
        external["metadata"]["annotations"]["heliopause.io/applier"] = "other-agent"
        self.cluster["util/hp-dev-p700"] = external
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("another applier", detail)
        self.assertFalse(any(c[0] in {"create", "replace"} for c in self.calls))
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-other-agent")

    def test_preflight_refuses_ambiguous_extra_controller_metadata(self):
        external = self.live(cnp(), uid="uid-flux", rv="9")
        external["metadata"]["labels"]["app.kubernetes.io/managed-by"] = "Flux"
        self.cluster["util/hp-dev-p700"] = external
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("exact heliopause ownership", detail)
        self.assertFalse(any(c[0] in {"create", "replace"} for c in self.calls))

    def test_create_race_refuses_without_overwriting_the_object_that_won(self):
        external = self.live(cnp(), uid="uid-flux", rv="9")
        external["metadata"]["labels"] = {
            "managed-by": "flux", "heliopause.io/cluster": "dev",
        }

        def race(args, stdin):
            if args[0] == "create":
                self.cluster["util/hp-dev-p700"] = external
            return None

        self.stub(race)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("AlreadyExists", detail)
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-flux")

    def test_replace_race_is_resource_version_bound(self):
        prior = self.live(cnp(), uid="uid-old", rv="1")
        prior["metadata"]["annotations"]["heliopause.io/generation"] = "g0"
        self.cluster["util/hp-dev-p700"] = prior

        def race(args, stdin):
            if args[0] == "replace":
                self.cluster["util/hp-dev-p700"]["metadata"]["resourceVersion"] = "9"
            return None

        self.stub(race)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("Conflict", detail)
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["resourceVersion"], "9")

    def test_read_back_refuses_same_uid_content_changed_after_write(self):
        changed = {"yes": False}

        def race(args, stdin):
            if "get" in args and "ciliumnetworkpolicy" in args and self.cluster and not changed["yes"]:
                self.cluster["util/hp-dev-p700"]["spec"]["description"] = "controller mutation"
                changed["yes"] = True
            return None

        self.stub(race)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("content changed during apply", detail)

    def test_rollback_leaves_a_replacement_with_a_different_uid_untouched(self):
        self.assertTrue(hp.apply_workload(self.artifact())[0])
        replacement = self.live(cnp(), uid="uid-controller", rv="8")
        replacement["metadata"]["annotations"]["heliopause.io/generation"] = "g2"
        self.cluster["util/hp-dev-p700"] = replacement
        self.assertFalse(hp.rollback_workload("stale timer", "g1"))
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-controller")
        self.assertEqual(self.deleted, [])

    def test_the_commitment_is_prepared_before_kubernetes_write_runs(self):
        checked = {"yes": False}

        def handler(args, _stdin):
            if args[0] in {"create", "replace"}:
                saved = hp.load_state()
                self.assertEqual(saved["workloadState"], "prepared")
                self.assertEqual(saved["workloadGeneration"], "g1")
                self.assertEqual(hp._workload_refs(saved["workloadApplied"]), ["util/hp-dev-p700"])
                checked["yes"] = True
            return None

        self.stub(handler)
        self.assertTrue(hp.apply_workload(self.artifact())[0])
        self.assertTrue(checked["yes"])

    def test_zero_pod_selector_is_reported_and_not_rolled_back(self):
        """A selector matching nothing is an observation, not a failed apply.

        This asserted a fail-closed gate, and the fleet showed what that means. The namespaces it
        fires on are ephemeral **by design** — `arc-runners` and `build-jobs` hold pods only while a
        CI job runs, and the design says so in as many words: 파드 0은 "안전"이 아니라 "지금 작업이
        없음". Gating on it means the workload half can never confirm while CI is idle, which is most
        of the time.

        Measured 2026-08-15 on k3s-01.dev: the first signed generation rolled its workload half back
        four times in a row with both namespaces legitimately empty and every object correctly
        applied. **A gate that fires in the normal state is not a gate.**

        So the count travels in the detail, where the relay surfaces it and an operator can tell
        "idle" from "inert" — the same call H30 makes for self-contradiction.
        """
        def handler(args, _stdin):
            if "get" in args and "pods" in args:
                return 0, "", ""
            return None

        self.stub(handler)
        ok, state, detail = hp.apply_workload(self.artifact())
        self.assertTrue(ok)
        self.assertEqual(state, "pending")
        self.assertIn("no pods", detail)

    def test_zero_pod_peer_selector_is_also_reported(self):
        obj = cnp()
        obj["spec"]["ingress"] = [{
            "fromEndpoints": [{
                "matchLabels": {hp.NS_LABEL: "arc-runners", "app": "runner"},
            }],
        }]

        def handler(args, _stdin):
            if "get" in args and "pods" in args:
                namespace = args[args.index("-n") + 1]
                return (0, "", "") if namespace == "arc-runners" else (0, "pod/zot-0\n", "")
            return None

        self.stub(handler)
        ok, state, detail = hp.apply_workload(self.artifact(objects=[obj]))
        self.assertTrue(ok)
        self.assertEqual(state, "pending")
        # Which side matched nothing still travels — a peer selector that reaches no pod is a
        # different fact from an endpointSelector that selects none, and the detail names it.
        self.assertIn("fromEndpoints", detail)

    def test_invalid_workload_timeout_is_refused_without_kubectl(self):
        ok, state, detail = hp.apply_workload(self.artifact(confirmTimeoutSec="forever"))
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("integer", detail)
        self.assertEqual(self.calls, [])

    def test_too_short_workload_timeout_is_refused_without_kubectl(self):
        ok, state, detail = hp.apply_workload(
            self.artifact(confirmTimeoutSec=hp.WORKLOAD_CONFIRM_MIN_SEC - 1)
        )
        self.assertFalse(ok)
        self.assertEqual(state, "unsupported")
        self.assertIn("between", detail)
        self.assertEqual(self.calls, [])

    def test_confirming_disarms_and_keeps_the_object_list(self):
        # The list is what a later rollback needs in order to know which objects are ours, so it
        # outlives the commitment.
        hp.apply_workload(self.artifact())
        st = hp.load_state()
        self.assertTrue(hp.confirm_workload(st))
        saved = hp.load_state()
        self.assertEqual(saved["workloadState"], "confirmed")
        self.assertIsNone(saved["workloadRollbackAt"])
        self.assertEqual(hp._workload_refs(saved["workloadApplied"]), ["util/hp-dev-p700"])
        self.assertIsNone(hp._wl_timer)

    def test_a_restart_inside_the_window_re_arms_rather_than_forgetting(self):
        # The objects are live in the cluster and nothing else would remove them.
        st = {**hp._EMPTY_STATE, "workloadState": "pending", "workloadGeneration": "g1",
              "workloadApplied": [{"ref": "util/hp-dev-p700", "uid": "uid-1", "cluster": "dev",
                                   "generation": "g1", "previous": None}],
              "workloadRollbackAt": time.time() + 120}
        hp.save_state(st)
        hp.recover_workload_commitment()
        self.assertIsNotNone(hp._wl_timer)
        self.assertEqual(self.calls, [], "re-arming must not touch the cluster")

    def test_a_restart_past_the_deadline_rolls_back_now(self):
        self.cluster["util/hp-dev-p700"] = self.live(cnp(), uid="uid-1", rv="2")
        st = {**hp._EMPTY_STATE, "workloadState": "pending", "workloadGeneration": "g1",
              "workloadApplied": [{"ref": "util/hp-dev-p700", "uid": "uid-1", "cluster": "dev",
                                   "generation": "g1", "previous": None}],
              "workloadRollbackAt": time.time() - 1}
        hp.save_state(st)
        hp.recover_workload_commitment()
        self.assertEqual(self.deleted, [("util/hp-dev-p700", "uid-1", "2")])
        self.assertEqual(hp.load_state()["workloadState"], "rolled-back")

    def test_prepared_restart_leaves_an_untouched_prior_object_alone(self):
        prior = self.live(cnp(), uid="uid-old", rv="7")
        prior["metadata"]["annotations"]["heliopause.io/generation"] = "g0"
        self.cluster["util/hp-dev-p700"] = prior
        record = {
            "ref": "util/hp-dev-p700", "uid": "uid-old", "cluster": "dev",
            "generation": "g1", "previous": hp._clean_workload_object(prior),
        }
        hp.save_state({
            **hp._EMPTY_STATE, "workloadState": "prepared", "workloadGeneration": "g1",
            "workloadApplied": [record], "workloadRollbackAt": time.time() + 300,
        })
        hp.recover_workload_commitment()
        self.assertEqual(self.deleted, [])
        self.assertFalse(any(args[0] == "replace" for args in self.calls))
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-old")
        self.assertEqual(hp.load_state()["workloadState"], "rolled-back")

    def test_prepared_restart_deletes_only_the_new_generation_object(self):
        self.cluster["util/hp-dev-p700"] = self.live(cnp(), uid="uid-new", rv="2")
        record = {
            "ref": "util/hp-dev-p700", "uid": None, "cluster": "dev",
            "generation": "g1", "previous": None,
        }
        hp.save_state({
            **hp._EMPTY_STATE, "workloadState": "prepared", "workloadGeneration": "g1",
            "workloadApplied": [record], "workloadRollbackAt": time.time() + 300,
        })
        hp.recover_workload_commitment()
        self.assertEqual(self.deleted, [("util/hp-dev-p700", "uid-new", "2")])
        self.assertEqual(hp.load_state()["workloadState"], "rolled-back")

    def test_prepared_restart_leaves_a_uid_replacement_as_an_incident(self):
        prior = self.live(cnp(), uid="uid-old", rv="1")
        prior["metadata"]["annotations"]["heliopause.io/generation"] = "g0"
        replacement = self.live(cnp(), uid="uid-replacement", rv="9")
        self.cluster["util/hp-dev-p700"] = replacement
        record = {
            "ref": "util/hp-dev-p700", "uid": "uid-old", "cluster": "dev",
            "generation": "g1", "previous": hp._clean_workload_object(prior),
        }
        hp.save_state({
            **hp._EMPTY_STATE, "workloadState": "prepared", "workloadGeneration": "g1",
            "workloadApplied": [record], "workloadRollbackAt": time.time() + 300,
        })
        hp.recover_workload_commitment()
        self.assertEqual(self.deleted, [])
        self.assertEqual(self.cluster["util/hp-dev-p700"]["metadata"]["uid"], "uid-replacement")
        self.assertEqual(hp.load_state()["workloadState"], "rollback-incident")

    def test_transient_delete_failure_is_retried_without_spending_identity_records(self):
        self.assertTrue(hp.apply_workload(self.artifact())[0])
        real_delete = hp._delete_workload_object
        hp._delete_workload_object = lambda *_args: (False, "API temporarily unavailable")
        try:
            self.assertFalse(hp.rollback_workload("injected transient failure", "g1"))
            saved = hp.load_state()
            self.assertEqual(saved["workloadState"], "rollback-failed")
            self.assertIsNotNone(saved["workloadApplied"])
            self.assertIsNotNone(hp._wl_timer)
        finally:
            hp._delete_workload_object = real_delete

    def test_confirmed_cross_layer_rollback_retries_when_its_state_save_fails(self):
        current = self.live(cnp(), uid="uid-1", rv="2")
        self.cluster["util/hp-dev-p700"] = current
        record = {
            "ref": "util/hp-dev-p700", "uid": "uid-1", "cluster": "dev",
            "generation": "g1", "previous": None,
        }
        hp.save_state({
            **hp._EMPTY_STATE,
            "workloadState": "confirmed", "workloadGeneration": "g1",
            "workloadApplied": [record], "workloadRollbackAt": None,
        })
        real_save = hp._save_state_unlocked
        hp._save_state_unlocked = lambda fresh: (
            False if fresh.get("workloadState") == "rolled-back" else real_save(fresh)
        )
        try:
            self.assertFalse(
                hp.rollback_workload("host counterpart failed", "g1", allow_confirmed=True)
            )
        finally:
            hp._save_state_unlocked = real_save
        self.assertEqual(hp.load_state()["workloadState"], "confirmed")
        self.assertEqual(hp._wl_rollback_owed, "g1")
        retry = hp._wl_timer
        self.assertIsNotNone(retry)
        retry.cancel()
        # Execute the captured retry synchronously: it must retain authority over the still-confirmed
        # durable state, observe the already-absent object, and settle the rollback.
        retry.function(*retry.args, **retry.kwargs)
        self.assertEqual(hp.load_state()["workloadState"], "rolled-back")
        self.assertIsNone(hp._wl_rollback_owed)

    def test_stale_workload_timer_cannot_cancel_a_new_same_generation_timer(self):
        old_deadline = time.time() - 1
        new_deadline = time.time() + 300
        new_timer = hp.threading.Timer(300, lambda: None)
        hp.save_state({
            **hp._EMPTY_STATE,
            "workloadState": "pending", "workloadGeneration": "g1",
            "workloadApplied": [{
                "ref": "util/hp-dev-p700", "uid": "uid-1", "cluster": "dev",
                "generation": "g1", "previous": None,
            }],
            "workloadRollbackAt": new_deadline,
        })
        hp._wl_timer = new_timer
        self.assertFalse(
            hp.rollback_generation("stale callback", "g1", "workload", old_deadline)
        )
        self.assertIs(hp._wl_timer, new_timer)

    def test_workload_confirmation_save_failure_keeps_rollback_armed(self):
        self.assertTrue(hp.apply_workload(self.artifact())[0])
        st = hp.load_state()
        real_save = hp._save_state_unlocked
        hp._save_state_unlocked = lambda fresh: (
            False if fresh.get("workloadState") == "confirmed" else real_save(fresh)
        )
        try:
            self.assertFalse(hp.confirm_workload(st))
        finally:
            hp._save_state_unlocked = real_save
        self.assertIsNotNone(hp._wl_timer)
        self.assertEqual(hp.load_state()["workloadState"], "pending")

    def test_slow_apply_cannot_extend_the_persisted_workload_deadline(self):
        real_time = hp.time
        now = {"value": 5_000.0}

        class Clock:
            def time(self):
                return now["value"]

            def __getattr__(self, name):
                return getattr(real_time, name)

        def slow_apply(args, _stdin):
            if args[0] in {"create", "replace"}:
                now["value"] += 301
            return None

        self.stub(slow_apply)
        hp.time = Clock()
        try:
            ok, state, detail = hp.apply_workload(self.artifact())
        finally:
            hp.time = real_time
        self.assertFalse(ok)
        self.assertEqual(state, "rolled-back")
        self.assertIn("deadline", detail)

    def test_restart_reconciliation_rolls_back_an_orphaned_workload_half(self):
        self.cluster["util/hp-dev-p700"] = self.live(cnp(), uid="uid-new", rv="2")
        hp.save_state({
            **hp._EMPTY_STATE,
            "generation": "g1", "state": "rolled-back",
            "workloadState": "pending", "workloadGeneration": "g1",
            "workloadApplied": [{
                "ref": "util/hp-dev-p700", "uid": "uid-new", "cluster": "dev",
                "generation": "g1", "previous": None,
            }],
            "workloadRollbackAt": time.time() + 120,
        })
        hp.reconcile_recovered_commitments()
        self.assertEqual(self.deleted, [("util/hp-dev-p700", "uid-new", "2")])
        self.assertEqual(hp.load_state()["workloadState"], "rolled-back")

    def test_no_commitment_means_nothing_to_recover(self):
        hp.recover_workload_commitment()
        self.assertIsNone(hp._wl_timer)
        self.assertEqual(self.calls, [])


class TestWorkloadHeartbeat(unittest.TestCase):
    """What the heartbeat says about the workload half.

    The relay distinguishes "absent" from "reported as failing", so a host with no assignment has to
    omit the key rather than send a null-filled object.
    """

    def setUp(self):
        self._real = hp.kubectl
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (0, "", "")
        with hp._workload_cache_lock:
            hp._workload_cache_key = None
            hp._workload_cache_observed = None
            hp._workload_cache_detail = ""
            hp._workload_cache_at = 0.0
            hp._workload_refreshing = False
        with hp._CILIUM_CACHE_LOCK:
            hp._CILIUM_CACHE = None
            hp._CILIUM_CACHE_AT = 0.0
            hp._CILIUM_REFRESHING = False
        with hp._host_observe_lock:
            hp._host_observe_value = None
            hp._host_observe_at = 0.0
            hp._host_observe_failure = ""
            hp._host_observe_refreshing = False

    def tearDown(self):
        hp.kubectl = self._real

    def test_omits_the_key_on_a_host_with_no_assignment(self):
        self.assertNotIn("workload", hp._workload_report(dict(hp._EMPTY_STATE)))

    def test_reports_the_state_and_reads_the_cluster_back(self):
        st = {**hp._EMPTY_STATE, "workloadState": "confirmed",
              "workloadGeneration": "g1", "workloadHash": "sha256:w1",
              "workloadApplied": ["util/hp-dev-p700"]}
        out = hp._workload_report(st)["workload"]
        self.assertEqual(out["state"], "confirmed")
        self.assertEqual(out["policiesHash"], "sha256:w1")
        self.assertIsNone(out["observed"], "the first heartbeat must not wait for kubectl")
        deadline = time.time() + 1
        while time.time() < deadline and out["observed"] is None:
            time.sleep(0.01)
            out = hp._workload_report(st)["workload"]
        self.assertEqual(out["observed"], ["util/hp-dev-p700"])

    def test_reports_null_observed_when_the_cluster_cannot_be_read(self):
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (1, "", "i/o timeout")
        st = {**hp._EMPTY_STATE, "workloadState": "confirmed",
              "workloadGeneration": "g1", "workloadApplied": ["util/hp-dev-p700"]}
        out = hp._workload_report(st)["workload"]
        self.assertIsNone(out["observed"], "unknown must not be reported as an empty set")
        deadline = time.time() + 1
        while time.time() < deadline and "i/o timeout" not in (out["detail"] or ""):
            time.sleep(0.01)
            out = hp._workload_report(st)["workload"]
        self.assertIn("i/o timeout", out["detail"])

    def test_slow_workload_and_cilium_reads_never_block_build_heartbeat(self):
        release = hp.threading.Event()
        entered = hp.threading.Event()

        def slow(_args, stdin=None, timeout_sec=None):
            entered.set()
            release.wait(1)
            return 1, "", "timed out"

        real_host_read = hp._read_host_observation
        hp.kubectl = slow

        def slow_host_read():
            entered.set()
            release.wait(1)
            return {
                "observed": "sha256:present", "detail": "",
                "foreignFilters": [], "publishedPorts": [],
            }

        hp._read_host_observation = slow_host_read
        st = {
            **hp._EMPTY_STATE,
            "workloadState": "pending",
            "workloadGeneration": "g1",
            "workloadApplied": ["util/hp-dev-p700"],
        }
        try:
            started = time.monotonic()
            heartbeat = hp.build_heartbeat(st)
            elapsed = time.monotonic() - started
        finally:
            release.set()
            deadline = time.time() + 1
            while time.time() < deadline:
                with hp._workload_cache_lock, hp._host_observe_lock:
                    if not hp._workload_refreshing and not hp._host_observe_refreshing:
                        break
                time.sleep(0.01)
            hp._read_host_observation = real_host_read
        self.assertLess(elapsed, 0.2)
        self.assertIsNone(heartbeat["workload"]["observed"])
        self.assertNotIn(
            "ciliumExposure", heartbeat,
            "least-privilege RBAC intentionally leaves privileged Cilium exec telemetry disabled",
        )
        self.assertTrue(entered.wait(1), "background observers never started")

    def _settle(self, st, want, timeout=1.0):
        """Beat until `want` appears in the detail, then return the last report."""
        out = hp._workload_report(st)["workload"]
        deadline = time.time() + timeout
        while time.time() < deadline and want not in (out["detail"] or ""):
            time.sleep(0.01)
            out = hp._workload_report(st)["workload"]
        return out

    def test_an_observer_that_raises_says_so_instead_of_saying_pending(self):
        """The reason must reach the heartbeat, not only the journal.

        The exception path used to leave the cache unwritten, so every later beat found no entry for
        this key and sent "refresh pending" — a word that promises an answer is coming. Measured
        2026-08-25 on k3s-01.dev: `observed` was null while 61 expected objects were in the cluster,
        the relay reported all of `mustExist` missing, and the row said pending. Nothing on it could
        be told apart from a first beat.
        """
        def boom(_refs, _deadline=None):
            raise OSError("kubeconfig vanished")

        real = hp.observed_objects
        hp.observed_objects = boom
        try:
            st = {**hp._EMPTY_STATE, "workloadState": "confirmed",
                  "workloadGeneration": "g1", "workloadApplied": ["util/hp-dev-p700"]}
            out = self._settle(st, "kubeconfig vanished")
        finally:
            hp.observed_objects = real
        self.assertIsNone(out["observed"], "a failed read is not an empty cluster")
        self.assertIn("workload observation failed", out["detail"])
        self.assertIn("kubeconfig vanished", out["detail"])
        self.assertNotIn(
            "refresh pending", out["detail"],
            "a failure that repeats must stop describing itself as not-yet-arrived",
        )

    def test_an_observer_that_cannot_start_is_retried_rather_than_latched(self):
        """`_workload_refreshing` is raised before the thread exists.

        A `start()` that raises would leave it True forever: no later beat starts another worker, and
        the cache freezes at whatever it last held while every heartbeat reports it as current. These
        hosts have under a gigabyte of RAM — thread creation is one of the first things to fail.
        """
        st = {**hp._EMPTY_STATE, "workloadState": "confirmed",
              "workloadGeneration": "g1", "workloadApplied": ["util/hp-dev-p700"]}

        class Refusing:
            def __init__(self, *a, **k):
                pass

            def start(self):
                raise RuntimeError("can't start new thread")

        real = hp.threading.Thread
        hp.threading.Thread = Refusing
        try:
            # Through `build_heartbeat`, not `_workload_report`, because that is where the sharper
            # failure is: nothing guards these calls, so an escaping spawn error leaves the heartbeat
            # unbuilt — and the heartbeat is the nft confirm signal. A host mid-apply would roll its
            # firewall back because it could not start a thread. Without the fix this errors here
            # rather than failing an assertion, and it takes all three spawn sites with it.
            heartbeat = hp.build_heartbeat(st)
        finally:
            hp.threading.Thread = real
        out = heartbeat["workload"]
        self.assertIsNone(out["observed"])
        self.assertIn("could not start", out["detail"])
        self.assertIn("could not start", heartbeat["applied"]["detail"])
        with hp._workload_cache_lock:
            self.assertFalse(
                hp._workload_refreshing,
                "a worker that never started must not hold the flag that stops the next one",
            )
        # The flag being clear is only worth anything if a later beat really does observe.
        out = hp._workload_report(st)["workload"]
        deadline = time.time() + 1
        while time.time() < deadline and out["observed"] is None:
            time.sleep(0.01)
            out = hp._workload_report(st)["workload"]
        self.assertEqual(out["observed"], ["util/hp-dev-p700"])

    def test_a_host_reader_that_raises_says_so_instead_of_saying_pending(self):
        """The same hole as the workload half, on the layer that decides rollback.

        `observed` stays null either way — `hasDrifted` reads null as drift, so this is already loud.
        What was wrong is the reason attached to it: "refresh pending" describes a first beat, and
        the failure that produced it will produce it again on every beat after.
        """
        def boom():
            raise OSError("nft is not on PATH")

        real = hp._read_host_observation
        hp._read_host_observation = boom
        try:
            st = {**hp._EMPTY_STATE, "workloadState": None}
            out = hp.build_heartbeat(st)["applied"]
            deadline = time.time() + 1
            while time.time() < deadline and "nft is not on PATH" not in (out["detail"] or ""):
                time.sleep(0.01)
                out = hp.build_heartbeat(st)["applied"]
        finally:
            hp._read_host_observation = real
        self.assertIsNone(out["observedHash"], "a failed read is not an empty ruleset")
        self.assertIn("host observation failed", out["detail"])
        self.assertIn("nft is not on PATH", out["detail"])
        self.assertNotIn("refresh pending", out["detail"])


class TestPreconditionedUnixSocketDelete(unittest.TestCase):
    def test_delete_uses_a_private_exact_path_socket_and_uid_preconditions(self):
        real_popen = hp.subprocess.Popen
        real_connection = hp._UnixHTTPConnection
        captured = {}

        class Proc:
            def __init__(self, cmd, **_kwargs):
                captured["cmd"] = cmd
                socket_arg = next(arg for arg in cmd if arg.startswith("--unix-socket="))
                captured["socket"] = socket_arg.split("=", 1)[1]
                with open(captured["socket"], "wb"):
                    pass

            def poll(self):
                return None

            def terminate(self):
                captured["terminated"] = True

            def wait(self, timeout=None):
                return 0

            def kill(self):
                captured["killed"] = True

            def communicate(self, timeout=None):
                return "", ""

        class Response:
            status = 200

            @staticmethod
            def read(_limit):
                return b"{}"

        class Connection:
            def __init__(self, socket_path, timeout):
                captured["connected"] = (socket_path, timeout)

            def request(self, method, path, body=None, headers=None):
                captured["request"] = (method, path, body, headers)

            @staticmethod
            def getresponse():
                return Response()

            @staticmethod
            def close():
                pass

        hp.subprocess.Popen = Proc
        hp._UnixHTTPConnection = Connection
        try:
            ok, detail = hp._delete_workload_object("util/hp-dev-p700", "uid-1", "rv-9")
        finally:
            hp.subprocess.Popen = real_popen
            hp._UnixHTTPConnection = real_connection

        self.assertTrue(ok, detail)
        method, path, body, _headers = captured["request"]
        self.assertEqual(method, "DELETE")
        self.assertEqual(path, "/apis/cilium.io/v2/namespaces/util/ciliumnetworkpolicies/hp-dev-p700")
        options = json.loads(body)
        self.assertEqual(options["preconditions"], {"uid": "uid-1", "resourceVersion": "rv-9"})
        self.assertIn("--unix-socket=" + captured["socket"], captured["cmd"])
        self.assertIn("--accept-paths=^" + hp.re.escape(path) + "$", captured["cmd"])
        self.assertFalse(os.path.exists(captured["socket"]))
        self.assertFalse(os.path.exists(os.path.dirname(captured["socket"])))
        self.assertTrue(captured.get("terminated"))


class TestKubeconfigBoundary(unittest.TestCase):
    def setUp(self):
        self.real_path = hp.KUBECONFIG
        self.real_namespaces = hp.WORKLOAD_NAMESPACES

    def tearDown(self):
        hp.KUBECONFIG = self.real_path
        hp.WORKLOAD_NAMESPACES = self.real_namespaces

    def test_has_no_implicit_cluster_admin_fallback(self):
        hp.KUBECONFIG = ""
        self.assertIn("no admin default", hp._kubeconfig_error())

    def test_explicitly_refuses_common_admin_kubeconfigs(self):
        hp.KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
        self.assertIn("cluster-admin", hp._kubeconfig_error())

    def test_requires_a_private_service_owned_regular_file(self):
        with tempfile.NamedTemporaryFile() as f:
            hp.KUBECONFIG = f.name
            os.chmod(f.name, 0o644)
            self.assertIn("group/world", hp._kubeconfig_error())

    def test_requires_an_explicit_namespace_allowlist(self):
        hp.WORKLOAD_NAMESPACES = frozenset()
        self.assertIn("namespace allowlist", hp._kubeconfig_error())


class TestWorkloadDisappearance(unittest.TestCase):
    """A confirmed generation whose objects are no longer in the cluster must be re-applied.

    Same shape as the measured nftables failure (mailer-01 rebooted, the table was gone, the state
    file still said `confirmed`, and the agent did nothing forever). The objects here do not live in
    kernel memory so a reboot does not take them — but `kubectl delete`, a flux prune, or a namespace
    being recreated all do, and the state file reads the same either way.
    """

    def setUp(self):
        self._real = hp.kubectl
        self.st = {**hp._EMPTY_STATE, "generation": "g1", "state": "confirmed",
                   "workloadState": "confirmed", "workloadGeneration": "g1",
                   "workloadApplied": ["util/hp-dev-p700"]}
        with hp._workload_cache_lock:
            hp._workload_cache_key = None
            hp._workload_cache_observed = None
            hp._workload_cache_detail = ""
            hp._workload_cache_at = 0.0
            hp._workload_refreshing = False

    def tearDown(self):
        hp.kubectl = self._real

    def test_reports_a_missing_object(self):
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (
            1, "", 'ciliumnetworkpolicy "hp-dev-p700" not found'
        )
        missing = hp._workload_objects_missing(self.st)
        deadline = time.time() + 1
        while time.time() < deadline and not missing:
            time.sleep(0.01)
            missing = hp._workload_objects_missing(self.st)
        self.assertIn("hp-dev-p700", missing)

    def test_is_quiet_when_every_object_is_present(self):
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (0, "", "")
        hp._workload_objects_missing(self.st)
        deadline = time.time() + 1
        while time.time() < deadline:
            with hp._workload_cache_lock:
                if hp._workload_cache_at:
                    break
            time.sleep(0.01)
        self.assertEqual(hp._workload_objects_missing(self.st), "")

    def test_an_unreadable_cluster_does_not_trigger_a_re_apply(self):
        # Not knowing must not act. The nftables side takes the same position: an unreadable dump is
        # reported as drift rather than acted on.
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (
            1, "", "Unable to connect to the server"
        )
        hp._workload_objects_missing(self.st)
        deadline = time.time() + 1
        while time.time() < deadline:
            with hp._workload_cache_lock:
                if hp._workload_cache_at:
                    break
            time.sleep(0.01)
        self.assertEqual(hp._workload_objects_missing(self.st), "")

    def test_a_pending_half_is_left_to_its_own_machinery(self):
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (1, "", "not found")
        st = {**self.st, "workloadState": "pending"}
        self.assertEqual(hp._workload_objects_missing(st), "")

    def test_a_host_with_no_assignment_has_nothing_to_check(self):
        called = []
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (
            called.append(args), (0, "", "")
        )[1]
        self.assertEqual(hp._workload_objects_missing(dict(hp._EMPTY_STATE)), "")
        self.assertEqual(called, [], "a host with no assignment must not query the cluster")


class TestSchemaVersion(unittest.TestCase):
    def test_is_not_below_what_the_relay_will_serve(self):
        # This used to assert `== 2` while the comment explained it was about not drifting below
        # `MIN_AGENT_SCHEMA` in src/protocol.ts. Those are different statements, and the difference
        # showed when the protocol moved to 3: the constant on both sides agreed and only the test
        # disagreed, so the failure said nothing about the relay and everything about the fixture.
        #
        # So read the other side instead of restating it. A relay that hands work only to agents at
        # or above `MIN_AGENT_SCHEMA` will silently stop serving this one if it falls behind, which
        # is correct behaviour and an outage either way — that is what deserves the test.
        protocol = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "protocol.ts")
        with open(protocol, encoding="utf-8") as handle:
            source = handle.read()
        declared = re.search(r"export const MIN_AGENT_SCHEMA = (\d+)", source)
        self.assertIsNotNone(declared, "MIN_AGENT_SCHEMA is no longer declared in src/protocol.ts")
        self.assertGreaterEqual(hp.SCHEMA_VERSION, int(declared.group(1)))



class TestSelectorMembership(unittest.TestCase):
    """What the applier reports about which pods a selector matches (H14a).

    The property that matters throughout: a namespace that could not be read is **omitted**, never
    reported as empty. The manager reads a missing key as "not known" and `[]` as "queried, and there
    are none" — and `arc-runners` is genuinely empty between CI jobs, so a failed query reported as
    `[]` would be indistinguishable from a healthy idle runner set.
    """

    def setUp(self):
        self._real = hp.kubectl
        self.calls = []
        with hp._membership_cache_lock:
            hp._membership_cache_key = None
            hp._membership_cache_value = None
            hp._membership_cache_at = 0.0
            hp._membership_refreshing = False

    def tearDown(self):
        hp.kubectl = self._real

    def stub(self, handler):
        def fake(args, stdin=None, timeout_sec=None):
            self.calls.append(args)
            return handler(args)
        hp.kubectl = fake

    def test_nothing_asked_means_nothing_reported(self):
        # The normal case on every host that is not the applier. An empty object would claim a query
        # happened on a host that never runs kubectl.
        self.stub(lambda a: (0, "", ""))
        self.assertIsNone(hp.selector_membership(None))
        self.assertIsNone(hp.selector_membership({}))
        self.assertEqual(self.calls, [], "a host with no watch list must not query the cluster")

    def test_reports_bare_pod_names_per_namespace(self):
        self.stub(lambda a: (0, "pod/runner-a\npod/runner-b\n", ""))
        m = hp.selector_membership({"namespaces": ["arc-runners"], "labels": []})
        self.assertEqual(m["namespaces"]["arc-runners"], ["runner-a", "runner-b"])
        # The manager qualifies these with the namespace it asked about, so a pod list can never be
        # attributed to the wrong namespace.
        self.assertNotIn("/", m["namespaces"]["arc-runners"][0])

    def test_an_empty_namespace_is_reported_as_empty(self):
        # Distinct from a failure. This is the state `arc-runners` is in between CI jobs.
        self.stub(lambda a: (0, "", ""))
        m = hp.selector_membership({"namespaces": ["arc-runners"], "labels": []})
        self.assertEqual(m["namespaces"]["arc-runners"], [])

    def test_a_failed_query_is_omitted_not_empty(self):
        # The distinction this whole field exists to preserve.
        self.stub(lambda a: (1, "", "Unable to connect to the server"))
        m = hp.selector_membership({"namespaces": ["arc-runners"], "labels": []})
        self.assertNotIn("arc-runners", m["namespaces"])
        self.assertIn("Unable to connect", m["detail"])

    def test_one_failure_does_not_lose_the_others(self):
        # A single unreadable namespace must not discard everything that was readable.
        def handler(args):
            return (1, "", "forbidden") if "broken" in args else (0, "pod/ok-a\n", "")
        self.stub(handler)
        m = hp.selector_membership({"namespaces": ["broken", "fine"], "labels": []})
        self.assertNotIn("broken", m["namespaces"])
        self.assertEqual(m["namespaces"]["fine"], ["ok-a"])

    def test_splits_the_cilium_namespace_label_out_of_a_selector(self):
        # `k8s:io.kubernetes.pod.namespace` is a Cilium-side label, not a Kubernetes one — kubectl
        # does not understand it. It scopes the query; the rest is the label selector.
        self.stub(lambda a: (0, "pod/idp-0\n", ""))
        sel = f"{hp.NS_LABEL}=idp,app=idp"
        m = hp.selector_membership({"namespaces": [], "labels": [sel]})
        args = self.calls[0]
        self.assertIn("-n", args)
        self.assertEqual(args[args.index("-n") + 1], "idp")
        self.assertEqual(args[args.index("-l") + 1], "app=idp")
        # Label matches come back qualified, unlike namespace listings.
        self.assertEqual(m["labelled"][sel], ["idp/idp-0"])

    def test_a_selector_naming_no_namespace_is_refused_without_a_cluster_wide_query(self):
        # A relay-controlled selector must not turn a bounded namespace read into --all-namespaces.
        self.stub(lambda a: (0, "", ""))
        self.assertIsNone(hp.selector_membership({"namespaces": [], "labels": ["app=idp"]}))
        self.assertEqual(self.calls, [])

    def test_carries_the_time_the_cluster_was_read(self):
        # Pod membership goes stale in seconds. A count without the time it was true is a number an
        # operator will read as current.
        self.stub(lambda a: (0, "", ""))
        m = hp.selector_membership({"namespaces": ["x"], "labels": []})
        self.assertRegex(m["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_the_heartbeat_omits_membership_when_nothing_was_asked(self):
        self.stub(lambda a: (0, "", ""))
        self.assertEqual(hp._membership_report(dict(hp._EMPTY_STATE)), {})

    def test_the_heartbeat_carries_membership_when_asked(self):
        self.stub(lambda a: (0, "pod/runner-a\n", ""))
        st = {**hp._EMPTY_STATE, "watchSelectors": {"namespaces": ["arc-runners"], "labels": []}}
        self.assertEqual(hp._membership_report(st), {})
        deadline = time.time() + 1
        out = {}
        while time.time() < deadline and "membership" not in out:
            time.sleep(0.01)
            out = hp._membership_report(st)
        self.assertEqual(out["membership"]["namespaces"]["arc-runners"], ["runner-a"])

    def test_an_oversized_watch_is_refused_before_querying(self):
        self.stub(lambda a: (0, "", ""))
        watch = {"namespaces": [f"x-{i}" for i in range(hp.MAX_WATCH_SELECTORS + 1)], "labels": []}
        parsed, reason = hp.validate_watch_selectors(watch)
        self.assertIsNone(parsed)
        self.assertIn("limit", reason)
        self.assertEqual(self.calls, [])

    def test_membership_collection_never_blocks_the_heartbeat(self):
        release = hp.threading.Event()

        def slow(_):
            release.wait(1)
            return 0, "pod/runner-a\n", ""

        self.stub(slow)
        st = {**hp._EMPTY_STATE, "watchSelectors": {"namespaces": ["arc-runners"], "labels": []}}
        started = time.monotonic()
        self.assertEqual(hp._membership_report(st), {})
        self.assertLess(time.monotonic() - started, 0.2)
        release.set()


class TestSignedWatchSurvivesHeartbeats(unittest.TestCase):
    """The selector watch comes from the signed manifest entry and must outlive an ordinary beat.

    ## Why this class exists, and why its absence is the whole story

    `handle_reply` used to read `watchSelectors` off the relay's reply. The relay does not send that
    field — `HeartbeatReply` is `{generation, gate, schemaVersion}` — so the read produced `None`,
    and `None != {...}` meant **every ordinary heartbeat overwrote the signed request with `None`.**
    The value written by `accept_artifact_authorization` survived about one interval.

    Nothing caught it, and the reason is exactly what this class fixes: **no test drove
    `handle_reply` with a watch in state at all.** The two tests above build a state dict by hand and
    call `_membership_report` directly, which never crosses the code that erased it.

    So this is the known positive for that deletion. Without it, removing the read and keeping it are
    indistinguishable — every other test passes either way, which is what "the fix is untested" looks
    like from the inside.
    """

    def setUp(self):
        self.saved = hp.load_state()
        hp.update_state(lambda st: st.update(dict(hp._EMPTY_STATE)))

    def tearDown(self):
        hp.update_state(lambda st: st.update(self.saved))

    #: What the relay actually replies with. Deliberately written out in full rather than built from
    #: a helper: the point of the test is that this shape carries no selector watch.
    ORDINARY_REPLY = {
        "generation": None,
        "gate": {"stage": "canary", "open": True},
        "schemaVersion": hp.SCHEMA_VERSION,
    }

    def test_an_ordinary_beat_keeps_the_signed_watch(self):
        signed = {"namespaces": ["arc-runners"], "labels": []}
        hp.update_state(lambda st: st.__setitem__("watchSelectors", signed))
        hp.handle_reply(hp.load_state(), dict(self.ORDINARY_REPLY))
        self.assertEqual(hp.load_state()["watchSelectors"], signed)

    def test_the_watch_still_answers_after_a_beat(self):
        # The consequence, not just the field. `_membership_report` returning `{}` is what the manager
        # sees as "this applier reports no membership", and that is what was true for every host.
        signed = {"namespaces": ["arc-runners"], "labels": []}
        hp.update_state(lambda st: st.__setitem__("watchSelectors", signed))
        hp.handle_reply(hp.load_state(), dict(self.ORDINARY_REPLY))
        parsed, reason = hp.validate_watch_selectors(hp.load_state().get("watchSelectors"))
        self.assertEqual(reason, "")
        self.assertEqual(parsed, signed)

    def test_a_relay_cannot_introduce_a_watch_of_its_own(self):
        # The other half: schema 3 says unsigned selector instructions were removed. A reply carrying
        # one must change nothing — neither adding a request where there was none...
        hostile = {"namespaces": ["arc-runners"], "labels": []}
        hp.handle_reply(hp.load_state(), {**self.ORDINARY_REPLY, "watchSelectors": hostile})
        self.assertIsNone(hp.load_state().get("watchSelectors"))

    def test_a_relay_cannot_replace_the_signed_watch(self):
        # ...nor narrowing or widening one the manager signed.
        signed = {"namespaces": ["arc-runners"], "labels": []}
        hp.update_state(lambda st: st.__setitem__("watchSelectors", signed))
        hp.handle_reply(hp.load_state(), {
            **self.ORDINARY_REPLY,
            "watchSelectors": {"namespaces": ["util", "idp"], "labels": []},
        })
        self.assertEqual(hp.load_state()["watchSelectors"], signed)


class TestPublishedPorts(unittest.TestCase):
    """H36 — ports another table DNATs inbound, which our rules never see.

    The parser is the whole risk here: it walks `nft -j list ruleset` and has to attribute a rule to a
    chain's hook without re-parsing indentation. So every case is measured against the shape podman's
    netavark table actually produces, not against an idea of it.
    """

    NETAVARK_DNAT = {
        "rule": {
            "family": "inet", "table": "netavark", "chain": "prerouting",
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}},
                {"dnat": {"addr": "10.88.0.5", "port": 80}},
            ],
        }
    }
    PREROUTING_CHAIN = {"chain": {"family": "inet", "table": "netavark", "name": "prerouting", "hook": "prerouting", "type": "nat"}}

    def _with(self, items):
        hp.nft = lambda args: (0, json.dumps({"nftables": items}), "")

    def test_reports_a_published_port_with_its_destination(self):
        self._with([self.PREROUTING_CHAIN, self.NETAVARK_DNAT])
        self.assertEqual(hp.published_ports(), ["inet netavark: tcp/8080 -> 10.88.0.5:80"])

    def test_ignores_our_own_forward_dnat_accept(self):
        # `ct status dnat accept` in our forward chain is a *consequence* of somebody else's DNAT, not a
        # publication. Reporting it would make every gateway accuse itself — measured on gw-01, that
        # rule is the only DNAT match in `inet heliopause`.
        self._with([
            {"chain": {"family": "inet", "table": hp.TABLE_NAME, "name": "forward", "hook": "forward", "type": "filter"}},
            {"rule": {"family": "inet", "table": hp.TABLE_NAME, "chain": "forward",
                      "expr": [{"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}}, {"accept": None}]}},
        ])
        self.assertEqual(hp.published_ports(), [])

    def test_ignores_postrouting_masquerade(self):
        # Egress NAT cannot expose a listener.
        self._with([
            {"chain": {"family": "inet", "table": "netavark", "name": "postrouting", "hook": "postrouting", "type": "nat"}},
            {"rule": {"family": "inet", "table": "netavark", "chain": "postrouting", "expr": [{"masquerade": None}]}},
        ])
        self.assertEqual(hp.published_ports(), [])

    def test_ignores_a_prerouting_rule_with_no_dnat(self):
        self._with([
            self.PREROUTING_CHAIN,
            {"rule": {"family": "inet", "table": "netavark", "chain": "prerouting",
                      "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}}]}},
        ])
        self.assertEqual(hp.published_ports(), [])

    def test_ignores_a_prerouting_dnat_in_our_own_table(self):
        # **This is the case that pins the table check, and the obvious one does not.**
        #
        # `test_ignores_our_own_forward_dnat_accept` above passes with the table check deleted, because
        # the hook check already rejects a `forward` chain. Injecting the defect proved it: removing the
        # table exclusion broke nothing. Only a DNAT in our table on `prerouting` reaches the point where
        # the table matters.
        self._with([
            {"chain": {"family": "inet", "table": hp.TABLE_NAME, "name": "prerouting", "hook": "prerouting", "type": "nat"}},
            {"rule": {"family": "inet", "table": hp.TABLE_NAME, "chain": "prerouting",
                      "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                               {"dnat": {"addr": "10.0.0.9", "port": 8443}}]}},
        ])
        self.assertEqual(hp.published_ports(), [])

    def test_ignores_a_dnat_outside_prerouting(self):
        # And this pins the hook check. `test_ignores_postrouting_masquerade` does not: masquerade has no
        # `dnat` key, so the DNAT check rejects it before the hook is consulted. A *DNAT* on postrouting
        # is what distinguishes the two.
        self._with([
            {"chain": {"family": "inet", "table": "netavark", "name": "postrouting", "hook": "postrouting", "type": "nat"}},
            {"rule": {"family": "inet", "table": "netavark", "chain": "postrouting",
                      "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 9999}},
                               {"dnat": {"addr": "10.88.0.7", "port": 90}}]}},
        ])
        self.assertEqual(hp.published_ports(), [])

    def test_none_when_the_kernel_cannot_be_read(self):
        # None and [] are different answers, and the relay keeps them apart. Collapsing them would
        # report "no published ports" on exactly the hosts where we cannot tell.
        hp.nft = lambda args: (1, "", "permission denied")
        self.assertIsNone(hp.published_ports())

    def test_none_on_unparseable_output(self):
        hp.nft = lambda args: (0, "not json", "")
        self.assertIsNone(hp.published_ports())

    def test_empty_list_when_there_are_none(self):
        self._with([])
        self.assertEqual(hp.published_ports(), [])

    def test_handles_a_dnat_without_a_port(self):
        # `dnat to <addr>` with no port is legal and redirects every port. Reported rather than skipped.
        self._with([
            self.PREROUTING_CHAIN,
            {"rule": {"family": "inet", "table": "netavark", "chain": "prerouting",
                      "expr": [{"dnat": {"addr": "10.88.0.9"}}]}},
        ])
        self.assertEqual(hp.published_ports(), ["inet netavark: ip/? -> 10.88.0.9"])


class TestCiliumExposure(unittest.TestCase):
    """The eBPF half of H36: the frontend exists without any nftables trace."""

    def setUp(self):
        self._real_kubectl = hp.kubectl
        self.calls = []

        self.rows = [{
            "spec": {
                "frontend-address": {"ip": "0.0.0.0", "port": 443, "protocol": "TCP"},
                "flags": {
                    "type": "HostPort", "namespace": "dispatcher",
                    "name": "dispatcher-abc:host-port:443:uuid-that-must-not-be-reported",
                },
            },
        }, {
            "spec": {
                "frontend-address": {"ip": "10.17.192.11", "port": 443, "protocol": "TCP"},
                "flags": {"type": "ClusterIP", "namespace": "dispatcher", "name": "dispatcher-mesh"},
            },
        }]

        def fake(args, stdin=None, timeout_sec=None):
            self.calls.append(args)
            if "configmap" in args:
                return 0, json.dumps({"data": {"nodeport-addresses": "10.17.0.0/18, 10.17.64.0/18"}}), ""
            if "pods" in args:
                return 0, json.dumps({"items": [{"metadata": {"name": "cilium-abc"}}]}), ""
            if "exec" in args:
                return 0, json.dumps(self.rows), ""
            return 1, "", "unexpected"
        hp.kubectl = fake

    def tearDown(self):
        hp.kubectl = self._real_kubectl

    def test_reports_only_host_facing_frontends_and_stable_names(self):
        self.assertEqual(hp._read_cilium_exposure(), {
            "nodePortAddresses": ["10.17.0.0/18", "10.17.64.0/18"],
            "services": ["HostPort 0.0.0.0:443/TCP dispatcher/dispatcher-abc"],
        })
        self.assertIn("cilium-dbg", self.calls[-1])

    def test_empty_address_setting_means_unrestricted(self):
        original = hp.kubectl
        def empty(args, stdin=None, timeout_sec=None):
            if "configmap" in args:
                return 0, json.dumps({"data": {"nodeport-addresses": ""}}), ""
            return original(args, stdin, timeout_sec)
        hp.kubectl = empty
        self.assertEqual(hp._read_cilium_exposure()["nodePortAddresses"], [])

    def test_returns_none_when_cilium_cannot_be_read(self):
        hp.kubectl = lambda args, stdin=None, timeout_sec=None: (1, "", "forbidden")
        self.assertIsNone(hp._read_cilium_exposure())


class TestStartupRequiresSigningConfiguration(unittest.TestCase):
    """`main()` refuses to run without what the signed-artifact path needs.

    The header has listed these three as required since the signing path was written, and the check
    had not caught up. Unset, the agent starts, authenticates and heartbeats — it looks healthy while
    refusing every generation, because `TARGET` defaults to `""` (so no real bundle's target matches)
    and an unconfigured key directory raises on first verification.

    Both fail closed, which is the right direction and the wrong signal: the error names the
    artifact, so a missing line in `agent.env` reads as a bad generation during a rollout.
    """

    def setUp(self):
        self.saved = {
            name: getattr(hp, name)
            for name in ("RELAY_URL", "CA_FILE", "CERT_FILE", "KEY_FILE",
                         "TARGET", "MANAGER_SIGNING_KEYS_DIR", "BREAK_GLASS_KEYS_DIR")
        }
        self.logged = []
        self.saved_log = hp.log
        hp.log = lambda line: self.logged.append(line)
        # A configuration that is complete apart from whatever each case removes, so a refusal can
        # only be about that one name. Trust loading is stubbed: this is about the guard, and the
        # loader has its own tests.
        hp.RELAY_URL = "https://relay.invalid:8443"
        hp.CA_FILE = "/dev/null"
        hp.CERT_FILE = "/dev/null"
        hp.KEY_FILE = "/dev/null"
        hp.TARGET = "dev"
        hp.MANAGER_SIGNING_KEYS_DIR = "/dev/null"
        hp.BREAK_GLASS_KEYS_DIR = "/dev/null"
        self.saved_trust = hp.load_artifact_trust

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(hp, name, value)
        hp.log = self.saved_log
        hp.load_artifact_trust = self.saved_trust

    def _run_main(self):
        """Run `main()` far enough to see the guard, without starting the agent.

        Signal installation is where a passing configuration stops, so it is the sentinel: reaching
        it means every check above returned. That keeps the known positive in the same test as the
        refusals — without it, each case below would pass just as well against a `main()` that
        rejected everything.
        """
        hp.load_artifact_trust = lambda: {
            "keys": {"sha256:aa": ("manager", "/x")},
            "managerKeyIds": ["sha256:aa"],
            "breakGlassKeyIds": ["sha256:bb"],
            "trustDigest": "sha256:cc",
        }
        reached = []

        class Reached(Exception):
            pass

        saved_signal = hp.signal.signal

        def stop(*_args, **_kwargs):
            reached.append(True)
            raise Reached()

        hp.signal.signal = stop
        try:
            return hp.main(), reached
        except Reached:
            return None, reached
        finally:
            hp.signal.signal = saved_signal

    def test_a_complete_configuration_gets_past_the_guard(self):
        code, reached = self._run_main()
        self.assertIsNone(code, "a complete configuration must not be refused")
        self.assertTrue(reached, "main() never reached startup")

    def test_missing_target_is_refused_by_name(self):
        hp.TARGET = ""
        code, reached = self._run_main()
        self.assertEqual(code, 2)
        self.assertFalse(reached)
        self.assertIn("HELIOPAUSE_TARGET", "\n".join(self.logged))

    def test_missing_manager_key_dir_is_refused_by_name(self):
        hp.MANAGER_SIGNING_KEYS_DIR = ""
        code, _ = self._run_main()
        self.assertEqual(code, 2)
        self.assertIn("HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR", "\n".join(self.logged))

    def test_missing_break_glass_key_dir_is_refused_by_name(self):
        hp.BREAK_GLASS_KEYS_DIR = ""
        code, _ = self._run_main()
        self.assertEqual(code, 2)
        self.assertIn("HELIOPAUSE_BREAK_GLASS_KEYS_DIR", "\n".join(self.logged))

    def test_unusable_trust_directory_exits_at_startup(self):
        """Not on the first artifact. A rollout is the worst place to learn the keyring is wrong."""
        def raise_it():
            raise ValueError("manager artifact key directory must be non-symlink and not group/world writable")

        code, reached = self._run_main()
        self.assertIsNone(code)  # the stubbed trust above is fine
        hp.load_artifact_trust = raise_it
        saved_signal = hp.signal.signal
        hp.signal.signal = lambda *a, **k: (_ for _ in ()).throw(AssertionError("started despite bad trust"))
        try:
            self.assertEqual(hp.main(), 2)
        finally:
            hp.signal.signal = saved_signal
        self.assertIn("artifact signing trust is unusable", "\n".join(self.logged))

    def test_an_unreadable_interval_is_refused_by_name(self):
        """A bad HELIOPAUSE_INTERVAL_SEC reads as a line in agent.env, not as a traceback.

        It used to be `int(os.environ.get(...))` at module scope, which put two failures in the
        wrong place: a non-numeric value raised `ValueError` **during import**, before this guard
        could say anything, and `0` was accepted — `sleep_interval` then returns immediately and the
        host heartbeats as fast as the relay will answer.
        """
        saved = hp.INTERVAL_ERROR
        try:
            hp.INTERVAL_ERROR = "HELIOPAUSE_INTERVAL_SEC must be a whole number of seconds between 1 and 3600 — got 'thirty'"
            code, reached = self._run_main()
            self.assertEqual(code, 2)
            self.assertFalse(reached, "started despite an unreadable interval")
            self.assertIn("HELIOPAUSE_INTERVAL_SEC", "\n".join(self.logged))
        finally:
            hp.INTERVAL_ERROR = saved


class TestIntervalParsing(unittest.TestCase):
    """`HELIOPAUSE_INTERVAL_SEC`, which is more than the sleep between beats.

    `NFT_CONFIRM_MIN_SEC` is derived from it — `max(90, 2 * INTERVAL_SEC, …)` — so a nonsense value
    does not merely change the polling rate, it moves the floor under the window the rollback timer
    honours. That is why this is parsed rather than coerced, and why the parser never raises: a
    module that cannot finish importing cannot print a sentence about why.
    """

    def test_unset_or_blank_is_the_default(self):
        for raw in (None, "", "   "):
            value, error = hp._interval_from_env(raw)
            self.assertIsNone(error, f"{raw!r} should be the default, not a refusal")
            self.assertEqual(value, hp.DEFAULT_INTERVAL_SEC)

    def test_a_whole_number_in_range_is_taken(self):
        self.assertEqual(hp._interval_from_env("30"), (30, None))
        self.assertEqual(hp._interval_from_env(" 30 "), (30, None))

    def test_a_non_number_is_reported_not_raised(self):
        value, error = hp._interval_from_env("thirty")
        # The default, so the constants derived below the parse stay computable. Nothing acts on
        # them because `main()` refuses first.
        self.assertEqual(value, hp.DEFAULT_INTERVAL_SEC)
        self.assertIn("HELIOPAUSE_INTERVAL_SEC", error)
        self.assertIn("thirty", error)

    def test_zero_and_negative_are_refused(self):
        """The hot loop. `_stop.wait(0)` returns immediately, from every host at once."""
        for raw in ("0", "-1"):
            _, error = hp._interval_from_env(raw)
            self.assertIsNotNone(error, f"{raw} must be refused")

    def test_an_interval_longer_than_the_confirm_ceiling_is_refused(self):
        """Past this the derived window would exceed NFT_CONFIRM_MAX_SEC and the two would disagree."""
        _, error = hp._interval_from_env(str(hp.MAX_INTERVAL_SEC + 1))
        self.assertIsNotNone(error)

    def test_a_float_is_refused_rather_than_truncated(self):
        _, error = hp._interval_from_env("15.9")
        self.assertIsNotNone(error, "a fraction must not silently become 15")


class TestWatchSelectorBounds(unittest.TestCase):
    """H7: a selector watch cannot make the heartbeat thread do unbounded serial kubectl work.

    `watchSelectors` arrives inside the **signed** `ManifestEntry.workload`, and the heartbeat
    thread answers it by running one `kubectl` per query, serially, with a timeout each. Unbounded,
    whoever authored that entry can hold the thread long past the confirm window, and on the applier
    the thread it holds is the one that confirms the host's own ruleset. The host then rolls back a
    healthy generation because nobody said "confirmed" in time: a firewall change reverted by a
    *reporting* request.

    ## This docstring used to say "arrives in the reply", and that sentence was the defect

    It did arrive in the reply, because `handle_reply` read it there — an unsigned field that
    `HeartbeatReply` does not declare and the relay never sends. Schema 3 states that it removed
    unsigned relay selector instructions; this was the line that had not been removed. The read is
    gone now and the bounds below are what remain, applied to the signed value.

    The bounds still matter after that change. A signed entry is authored by the manager, and the
    manager renders it from policy — so an overlong selector is a policy mistake rather than an
    attack, and it reaches the same serial kubectl loop either way.

    So the bounds are the fix, and each is tested against a request that is valid in every other
    respect — otherwise a refusal proves only that the fixture was malformed.
    """

    def _accepted(self, watch):
        result, reason = hp.validate_watch_selectors(watch)
        self.assertEqual(reason, "")
        return result

    def test_a_normal_request_is_accepted(self):
        # The known positive. Without it every refusal below could pass because the function rejects
        # everything, which is also what a broken fixture looks like.
        ok = self._accepted({"namespaces": ["arc-runners"], "labels": [f"{hp.NS_LABEL}=util,app=runner"]})
        self.assertEqual(ok["namespaces"], ["arc-runners"])

    def test_too_many_queries_is_refused(self):
        watch = {"namespaces": ["arc-runners"] * (hp.MAX_WATCH_SELECTORS + 1), "labels": []}
        result, reason = hp.validate_watch_selectors(watch)
        self.assertIsNone(result)
        self.assertIn("limit is", reason)

    def test_an_overlong_selector_is_refused(self):
        # Bounded by bytes, not characters: the cost is what kubectl has to carry.
        long_value = "a" * (hp.MAX_SELECTOR_BYTES + 1)
        result, reason = hp.validate_watch_selectors({"namespaces": [], "labels": [f"{hp.NS_LABEL}=util,app={long_value}"]})
        self.assertIsNone(result)
        self.assertIn("overlong", reason)

    def test_too_many_terms_in_one_selector_is_refused(self):
        terms = ",".join(f"k{i}=v" for i in range(hp.MAX_SELECTOR_TERMS + 1))
        result, reason = hp.validate_watch_selectors({"namespaces": [], "labels": [f"{hp.NS_LABEL}=util,{terms}"]})
        self.assertIsNone(result)
        self.assertIn("too many", reason)

    def test_a_namespace_outside_the_allowlist_is_refused(self):
        # The bound that is about reach rather than cost: a query the operator never authorised is
        # one this agent's RBAC may still answer, and the answer goes back over the heartbeat.
        result, reason = hp.validate_watch_selectors({"namespaces": ["kube-system"], "labels": []})
        self.assertIsNone(result)
        self.assertIn("may query", reason)

    def test_a_peer_namespace_may_be_queried_without_being_writable(self):
        # The split this bound now respects: a membership query is a read. A namespace we may look at
        # is not a namespace we may create a CiliumNetworkPolicy in — and an egress allow-list has to
        # name `kube-system`, because DNS is CoreDNS and no CIDR reaches a pod-backed destination.
        real = hp.WORKLOAD_PEER_NAMESPACES
        hp.WORKLOAD_PEER_NAMESPACES = real | {"kube-system"}
        try:
            result, reason = hp.validate_watch_selectors(
                {"namespaces": ["kube-system"], "labels": [f"{hp.NS_LABEL}=kube-system,k8s-app=kube-dns"]}
            )
            self.assertEqual(reason, "")
            self.assertEqual(result["namespaces"], ["kube-system"])
        finally:
            hp.WORKLOAD_PEER_NAMESPACES = real
        # And writing there is still refused: the object's own namespace is checked against the
        # writable list, which this did not widen.
        doc, reason = validate_wl(wl(cnp(namespace="kube-system")))
        self.assertIsNone(doc)
        self.assertIn("HELIOPAUSE_K8S_NAMESPACES", reason)

    def test_an_unpinned_selector_is_refused(self):
        # Without the namespace label the query would fall back to every namespace — the expensive
        # case this bound exists to keep out of the heartbeat path.
        result, reason = hp.validate_watch_selectors({"namespaces": [], "labels": ["app=runner"]})
        self.assertIsNone(result)
        self.assertIn("does not pin", reason)


class TestWorkloadOwnershipBoundary(unittest.TestCase):
    """H4/H5: what the agent is allowed to overwrite, and what it is allowed to delete.

    `kubectl apply` is name-addressed. A CiliumNetworkPolicy that flux owns, or that another applier
    wrote, or that belongs to a different cluster, answers to the same name — so an apply would
    silently take it over, and the rollback that follows would then delete an object heliopause never
    created. Both halves of that were fixed and **neither was exercised**: `_owned_object_error` had
    zero callers in this suite, so every refusal below could have been deleted without a test
    noticing.

    Each case starts from an object this agent *would* accept and breaks exactly one thing. A fixture
    that is wrong in several ways at once proves only that something was refused.
    """

    CLUSTER = "dev"

    def _owned(self, **over):
        meta = {
            "name": f"hp-{hp._slug(self.CLUSTER)}-dev-k3s-manager",
            "namespace": "heliopause",
            "labels": {"managed-by": hp.WORKLOAD_MANAGED_BY, "heliopause.io/cluster": self.CLUSTER},
            "annotations": {
                "heliopause.io/policy-id": "DEV-K3S-MANAGER",
                "heliopause.io/applier": hp.HOST_ID,
                "heliopause.io/generation": "gen-1",
            },
            "uid": "11111111-2222-3333-4444-555555555555",
        }
        meta.update(over.pop("metadata", {}))
        obj = {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": meta, "spec": {}}
        obj.update(over)
        return obj

    def _ref(self, obj):
        return f"{obj['metadata']['namespace']}/{obj['metadata']['name']}"

    def test_our_own_object_is_accepted(self):
        # The known positive. Without it every refusal below passes against a function that refuses
        # everything — which is also what a broken fixture looks like.
        obj = self._owned()
        self.assertEqual(hp._owned_object_error(obj, self._ref(obj), self.CLUSTER), "")

    def test_an_object_without_our_label_is_refused(self):
        # The flux case. It is the one that matters most: the object exists, the name matches, and
        # apply would take it over without this.
        obj = self._owned()
        obj["metadata"]["labels"] = {"app.kubernetes.io/managed-by": "flux"}
        self.assertIn("refusing external object", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_extra_labels_are_refused_even_with_ours_present(self):
        # Ownership is the *exact* set, not a superset. A controller that adds its own label to our
        # object is a controller that also reconciles it, and overwriting that is a fight, not a fix.
        obj = self._owned()
        obj["metadata"]["labels"]["kustomize.toolkit.fluxcd.io/name"] = "apps"
        self.assertIn("outside the exact heliopause ownership set", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_another_cluster_is_refused(self):
        obj = self._owned()
        obj["metadata"]["labels"]["heliopause.io/cluster"] = "util"
        self.assertIn("belongs to cluster", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_another_applier_is_refused(self):
        # Cluster-scoped objects with several agents running is the case this prevents: two appliers
        # writing the same name is API contention and flapping, not redundancy.
        obj = self._owned()
        obj["metadata"]["annotations"]["heliopause.io/applier"] = "someone-else.dev"
        self.assertIn("another applier", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_a_name_that_does_not_match_its_policy_id_is_refused(self):
        # The annotation is what `mustExist` and the rollback both key on. A name that disagrees with
        # it means one of the two is about a different object.
        obj = self._owned()
        obj["metadata"]["annotations"]["heliopause.io/policy-id"] = "SOME-OTHER-POLICY"
        self.assertIn("does not match its heliopause policy-id", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_a_missing_uid_is_refused(self):
        # H5. The UID is not bookkeeping: the rollback delete carries it as a precondition, so an
        # object captured without one would be deleted by name — and by then it may be a *different*
        # object that a controller recreated under that name.
        obj = self._owned()
        del obj["metadata"]["uid"]
        self.assertIn("no Kubernetes UID", hp._owned_object_error(obj, self._ref(obj), self.CLUSTER))

    def test_a_generation_that_moved_on_is_refused_at_rollback(self):
        # Rollback is scoped to the generation it was armed for. If something published over us in
        # the meantime, restoring our old object would undo a newer, approved change.
        obj = self._owned()
        error = hp._owned_object_error(obj, self._ref(obj), self.CLUSTER, generation="gen-0")
        self.assertIn("not rollback generation", error)

    def test_a_read_back_under_a_different_name_is_refused(self):
        obj = self._owned()
        error = hp._owned_object_error(obj, "heliopause/something-else", self.CLUSTER)
        self.assertIn("different name or namespace", error)


class TestReplyIsolation(unittest.TestCase):
    """M7: one malformed reply must not end the agent.

    The heartbeat loop is also the confirm path. An exception escaping reply handling kills the
    thread that would confirm this host's own ruleset, so a bad reply from the relay becomes a
    rollback of a healthy generation — and then the loop is gone and the host stops updating at all.
    """

    def test_a_reply_that_raises_is_contained(self):
        saved = hp.handle_reply
        try:
            def boom(_st, _reply):
                raise ValueError("artifact is nonsense")

            hp.handle_reply = boom
            self.assertFalse(hp.handle_reply_safely({}, {"schemaVersion": hp.SCHEMA_VERSION}))
        finally:
            hp.handle_reply = saved

    def test_a_reply_that_is_not_an_object_is_contained(self):
        self.assertFalse(hp.handle_reply_safely({}, ["not", "an", "object"]))

    def test_a_normal_reply_still_reaches_the_handler(self):
        # The known positive: containment that swallowed everything would pass both cases above.
        saved = hp.handle_reply
        seen = []
        try:
            hp.handle_reply = lambda _st, reply: seen.append(reply)
            self.assertTrue(hp.handle_reply_safely({}, {"schemaVersion": hp.SCHEMA_VERSION}))
        finally:
            hp.handle_reply = saved
        self.assertEqual(len(seen), 1)


class TestSignedArtifactSeam(unittest.TestCase):
    """The apply path must run the fetched envelope through verification.

    `verify_artifact_envelope` and `accept_artifact_authorization` both had **zero callers** — here
    and in the agent — so the signature the whole path exists for was never checked. What the fleet
    saw was quieter than a failure: `fetch_artifact()` returns the envelope, the envelope has no
    `generation`, and every beat logged "artifact is generation None" and applied nothing. Measured
    2026-08-15 on the first fleet-wide rollout.

    A unit test of the verifier would have passed throughout. So this tests the **seam**: that the
    apply path calls it, in the right order, and refuses rather than raising when it says no.
    """

    def _source(self):
        # `handle_reply`, named rather than guessed. The first version of this test asked for
        # `apply_generation` "if it exists" and silently fell back — and the fallback read a function
        # that did not contain the seam, so removing the verification call left it green. A test that
        # picks its own subject at runtime cannot say what it failed to find.
        import inspect
        assert hasattr(hp, "handle_reply"), "handle_reply is gone — this test is about its seam"
        source = inspect.getsource(hp.handle_reply)
        # Comments stripped, and that is not tidiness. The seam is explained in a comment that names
        # the same functions, so `assertIn` passed against a body whose **call** had been removed —
        # the check was reading the explanation instead of the code. Caught by defect injection.
        return "\n".join(line for line in source.split("\n") if not line.lstrip().startswith("#"))

    def test_the_apply_path_verifies_before_it_reads_a_generation(self):
        # Order matters as much as presence: reading `generation` off the raw envelope is what the
        # fleet did for an hour, and it reads as "the relay is behind" rather than "nothing verifies".
        src = self._source()
        self.assertIn("verify_artifact_envelope", src, "the apply path does not verify the envelope")
        verify_at = src.index("verify_artifact_envelope")
        gen_at = src.index('artifact.get("generation")')
        self.assertLess(verify_at, gen_at, "the generation is read before the envelope is verified")

    def test_the_apply_path_advances_the_replay_watermark(self):
        # Durably, and before any kernel or kubectl side effect — a crash between apply and record
        # leaves a window where the same authorization can be replayed.
        src = self._source()
        self.assertIn("accept_artifact_authorization", src, "the apply path does not record replay state")
        accept_at = src.index("accept_artifact_authorization")
        preflight_at = src.index("_preflight_host_artifact")
        self.assertLess(accept_at, preflight_at, "the watermark is advanced after the host half is touched")

    def test_a_refused_envelope_returns_instead_of_raising(self):
        # The heartbeat thread is also the confirm path. An exception escaping here kills the thread
        # that would confirm this host's own ruleset — M7, one level up.
        src = self._source()
        self.assertIn('log(f"refusing artifact for generation', src)
        self.assertIn("except Exception as e:", src)


def _openssl_has_rawin():
    """Does the binary the **agent** uses support `-rawin`?

    Not the one on `$PATH`. macOS ships LibreSSL at `/usr/bin/openssl` and it has no `-rawin`, while
    a brew OpenSSL earlier in `$PATH` does — so a check that asked the shell would answer about a
    binary the agent never calls, and the suite would look covered on a laptop where this path cannot
    run at all. The fleet hosts are Rocky with OpenSSL 3, and CI is ubuntu-latest, so these run where
    it matters.
    """
    try:
        out = subprocess.run([hp.OPENSSL, "pkeyutl", "-help"], capture_output=True, text=True, timeout=10)
        return "-rawin" in (out.stdout + out.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(_openssl_has_rawin(), "the agent's openssl has no -rawin (LibreSSL on macOS)")
class TestEd25519Verification(unittest.TestCase):
    """`_verify_ed25519` against a signature this test actually produced.

    Nothing exercised it. The agent shelled out to `openssl pkeyutl -verify -rawin` with the message
    on **stdin**, and `-rawin` is a oneshot operation: OpenSSL asks the input for its size before it
    starts and a pipe cannot answer, so it failed before any cryptography happened — with a non-zero
    exit that reads exactly like a bad signature.

    Measured 2026-08-15 on gw-01.util with OpenSSL 3.5.1: one signature verified from a file and
    failed from a pipe. The whole fleet refused every artifact as "signature is invalid" while the
    signatures were correct, which is the worst shape this could take — the message accuses the
    manager, and the manager was right.

    So the known positive is the point of this test: a signature made here must verify here.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="heliopause-ed25519-")
        self.key = os.path.join(self.dir, "k.key")
        self.pub = os.path.join(self.dir, "k.pub")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", self.key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", self.pub],
                       check=True, capture_output=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _sign(self, message):
        msg = os.path.join(self.dir, "m.bin")
        sig = os.path.join(self.dir, "s.bin")
        with open(msg, "wb") as f:
            f.write(message)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", msg, "-out", sig],
                       check=True, capture_output=True)
        with open(sig, "rb") as f:
            return f.read()

    def test_a_signature_we_made_verifies(self):
        # The known positive. Without it every negative below passes against a verifier that refuses
        # everything — which is exactly what shipped.
        message = b"heliopause artifact authorization"
        self.assertTrue(hp._verify_ed25519(self.pub, message, self._sign(message)))

    def test_a_large_message_verifies(self):
        # An artifact payload is kilobytes, not bytes. A path that only works below the pipe buffer
        # would pass a small fixture and fail on every real generation.
        message = b"x" * 200_000
        self.assertTrue(hp._verify_ed25519(self.pub, message, self._sign(message)))

    def test_a_tampered_message_does_not_verify(self):
        message = b"heliopause artifact authorization"
        signature = self._sign(message)
        self.assertFalse(hp._verify_ed25519(self.pub, message + b"!", signature))

    def test_another_key_does_not_verify(self):
        other = os.path.join(self.dir, "o.pub")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", os.path.join(self.dir, "o.key")],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", os.path.join(self.dir, "o.key"), "-pubout", "-out", other],
                       check=True, capture_output=True)
        message = b"heliopause artifact authorization"
        self.assertFalse(hp._verify_ed25519(other, message, self._sign(message)))

    def test_it_leaves_no_message_or_signature_file_behind(self):
        # Both are written beside the state file. A verifier that leaks one temp file per heartbeat
        # fills the state directory, and the state directory is where the rollback commitment lives.
        before = set(os.listdir(os.path.dirname(hp.STATE_FILE) or "."))
        message = b"heliopause artifact authorization"
        hp._verify_ed25519(self.pub, message, self._sign(message))
        after = set(os.listdir(os.path.dirname(hp.STATE_FILE) or "."))
        self.assertEqual(before, after)


@unittest.skipUnless(_openssl_has_rawin(), "the agent's openssl has no -rawin (LibreSSL on macOS)")
class TestSignedRoutesReachTheApplier(unittest.TestCase):
    """A routed manifest entry, signed here, verified here, arriving as an applyable artifact.

    ## Why this is a round trip rather than a unit test

    The routing half was unreachable in a way no unit test could show. `planPublish` emitted
    `routes` and `routeGuard`; the signer's entry validator refused unknown keys; the agent's did
    too; and `verify_artifact_envelope` assembled its artifact dict without them. Four places, each
    self-consistent, and the failure only appears when a routed entry crosses all four.

    So this builds the envelope the way the manager does — canonical JSON, the same length-framed
    signature input, a real Ed25519 key — and asserts what comes out the other end is something
    `apply_artifact` can act on. `SIGN FAILED: payload.entry has unsupported or missing fields` was
    the old answer, from the manager's side; this is the agent's.
    """

    def setUp(self):
        # ## This class needs the real verifier, and the module stubs it globally
        #
        # `stub_artifact_verification()` runs at import so the apply-path tests can hand
        # `fetch_artifact` a plain dict. Its own comment names the cost: "what is **not** covered
        # here is `verify_artifact_envelope`'s own behaviour — that needs key fixtures, and its
        # absence is the reason the missing call went unnoticed for a fleet-wide rollout."
        #
        # This is that coverage, so the stub is lifted for the duration and put back after — without
        # it these tests assert against a lambda that returns whatever it was handed, which passes
        # every positive and fails every negative. Measured: that is exactly what happened first.
        self.NOW = hp._exact_iso(self.AUTHORIZED_AT, "fixture") + 3600
        self._stubbed = (hp.verify_artifact_envelope, hp.accept_artifact_authorization)
        _RESTORE_VERIFICATION()
        self.dir = tempfile.mkdtemp(prefix="heliopause-routes-")
        self.keys = os.path.join(self.dir, "manager")
        self.empty = os.path.join(self.dir, "break-glass")
        os.makedirs(self.keys, mode=0o700)
        os.makedirs(self.empty, mode=0o700)
        self.key = os.path.join(self.dir, "k.key")
        pub = os.path.join(self.keys, "manager.pub")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", self.key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", pub],
                       check=True, capture_output=True)
        self.saved = (hp.MANAGER_SIGNING_KEYS_DIR, hp.BREAK_GLASS_KEYS_DIR, hp._artifact_keys_cache)
        hp.MANAGER_SIGNING_KEYS_DIR = self.keys
        hp.BREAK_GLASS_KEYS_DIR = self.empty
        hp._artifact_keys_cache = None

    def tearDown(self):
        hp.verify_artifact_envelope, hp.accept_artifact_authorization = self._stubbed
        hp.MANAGER_SIGNING_KEYS_DIR, hp.BREAK_GLASS_KEYS_DIR, hp._artifact_keys_cache = self.saved
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    RULESET = '{"nftables":[{"add":{"table":{"family":"inet","name":"heliopause"}}}]}'
    AUTHORIZED_AT = "2026-08-20T00:00:00.000Z"
    EXPIRES_AT = "2026-08-20T06:00:00.000Z"
    #: Inside the signed window, derived from it rather than written as an epoch — a literal drifts
    #: out of the window the moment either timestamp moves, and the failure reads as "expired".
    NOW = None  # set in setUp, once hp is known to be loaded

    def _entry(self, **over):
        entry = {
            "stage": "canary",
            "rulesetHash": "sha256:" + hashlib.sha256(self.RULESET.encode()).hexdigest(),
            "confirmTimeoutSec": hp.NFT_CONFIRM_MIN_SEC,
            "mustContain": ["baseline: loopback"],
            "routes": [{"dst": "10.17.128.0/18", "via": "10.17.0.9"}],
            "routeGuard": ["10.17.0.0/16"],
        }
        for key, value in over.items():
            if value is None:
                entry.pop(key, None)
            else:
                entry[key] = value
        return entry

    def _envelope(self, entry):
        """Exactly what `signHostArtifactAuthorization` produces, built by hand.

        Canonical JSON and the framed signature input are copied from the agent's own constants
        rather than restated, so a change to either fails here instead of drifting silently.
        """
        bundle_hash = "sha256:" + "0" * 64
        plan_material = (hp._frame(b"heliopause-plan-v1") + hp._frame(hp.TARGET.encode())
                         + hp._frame(bundle_hash.encode()))
        payload = {
            "version": 1,
            "target": hp.TARGET,
            "planHash": "sha256:" + hashlib.sha256(plan_material).hexdigest(),
            "bundleHash": bundle_hash,
            "authorizedAt": self.AUTHORIZED_AT,
            "expiresAt": self.EXPIRES_AT,
            "authorizationMode": "two-person",
            "host": hp.HOST_ID,
            "manifest": {
                "generation": "abc1234",
                "issuedAt": "2026-08-19T23:59:00.000Z",
                "schemaVersion": hp.SCHEMA_VERSION,
            },
            "entry": entry,
            "ruleset": self.RULESET,
            "workload": None,
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")

        pub_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", os.path.join(self.keys, "manager.pub"),
             "-outform", "DER"], check=True, capture_output=True).stdout
        key_id = "sha256:" + hashlib.sha256(pub_der).hexdigest()

        message = hp._frame(hp.SIGNATURE_DOMAIN) + hp._frame(key_id.encode()) + hp._frame(raw)
        msg_path = os.path.join(self.dir, "m.bin")
        sig_path = os.path.join(self.dir, "s.bin")
        with open(msg_path, "wb") as f:
            f.write(message)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self.key, "-rawin",
                        "-in", msg_path, "-out", sig_path], check=True, capture_output=True)
        with open(sig_path, "rb") as f:
            signature = f.read()
        return {
            "version": hp.ENVELOPE_VERSION,
            "algorithm": "Ed25519",
            "keyId": key_id,
            "payload": base64.urlsafe_b64encode(raw).decode().rstrip("="),
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }

    # The known positive, and the first time a routed entry has reached this function at all.
    def test_a_routed_entry_becomes_an_applyable_artifact(self):
        artifact, _record, _watch, expired = hp.verify_artifact_envelope(
            self._envelope(self._entry()), now=self.NOW)
        self.assertFalse(expired)
        self.assertEqual(artifact["routes"], [{"dst": "10.17.128.0/18", "via": "10.17.0.9"}])
        self.assertEqual(artifact["routeGuard"], ["10.17.0.0/16"])

    def test_an_entry_without_routes_still_verifies_and_carries_none(self):
        # Every host in the fleet is this case. Adding the fields must not make them mandatory, and
        # absent must stay absent — `apply_artifact` reads `artifact.get("routes")` and an empty list
        # planted here would be a field on every host's artifact that only one host ever uses.
        artifact, _r, _w, _e = hp.verify_artifact_envelope(
            self._envelope(self._entry(routes=None, routeGuard=None)), now=self.NOW)
        self.assertNotIn("routes", artifact)
        self.assertNotIn("routeGuard", artifact)

    def test_routes_without_a_guard_are_refused(self):
        with self.assertRaises(ValueError) as caught:
            hp.verify_artifact_envelope(self._envelope(self._entry(routeGuard=None)), now=self.NOW)
        self.assertIn("management guard", str(caught.exception))

    def test_an_empty_guard_is_refused(self):
        # `managementGuard` returns `[]` for a baseline whose entries name no source — this site's
        # shape. The old check was `isinstance(guard, list)`, which accepted exactly that and then
        # protected nothing.
        with self.assertRaises(ValueError) as caught:
            hp.verify_artifact_envelope(self._envelope(self._entry(routeGuard=[])), now=self.NOW)
        self.assertIn("management guard", str(caught.exception))

    def test_a_guard_without_routes_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            hp.verify_artifact_envelope(self._envelope(self._entry(routes=None)), now=self.NOW)
        self.assertIn("route guard with no routes", str(caught.exception))

    def test_a_route_spec_with_unknown_fields_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            hp.verify_artifact_envelope(
                self._envelope(self._entry(routes=[{"dst": "10.17.128.0/18", "note": "why"}])),
                now=self.NOW)
        self.assertIn("unsupported or missing fields", str(caught.exception))

    def test_a_relay_cannot_append_a_route_to_a_signed_entry(self):
        # The property the envelope exists for, stated for this field: a courier that adds a default
        # route must not produce something this agent applies.
        envelope = self._envelope(self._entry())
        payload = json.loads(base64.urlsafe_b64decode(
            envelope["payload"] + "=" * (-len(envelope["payload"]) % 4)))
        payload["entry"]["routes"].append({"dst": "0.0.0.0/0", "via": "203.0.113.1"})
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        envelope["payload"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        with self.assertRaises(ValueError) as caught:
            hp.verify_artifact_envelope(envelope, now=self.NOW)
        self.assertIn("signature is invalid", str(caught.exception))



class RoutesFromJson(unittest.TestCase):
    """The parser behind `Heartbeat.routes`.

    A packet reaches a filter only if routing sent it there, and this agent reported only the filter.
    Measured on gw-01.dev on 2026-08-16: two `proto static` routes carry every packet bound for the
    cluster's pod and service ranges, and neither is written down anywhere but that kernel.
    """

    def test_marks_a_static_route_as_written_by_a_person(self):
        # The known positive, taken from the live gateway rather than invented.
        rows = [{"dst": "10.17.128.0/18", "gateway": "10.17.0.10", "dev": "enp8s0",
                 "protocol": "static", "table": "main"}]
        out = hp._routes_from_json(rows)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["origin"], "static")
        self.assertTrue(out[0]["handAdded"])
        self.assertEqual(out[0]["via"], "10.17.0.10")

    def test_leaves_routes_with_an_owner_alone(self):
        # A route the kernel, a DHCP lease or a routing daemon put there has somewhere else to be
        # looked up. Flagging those too would make the column noise, and a noisy column is unread.
        for proto in ("kernel", "dhcp", "ra", "bird"):
            out = hp._routes_from_json([{"dst": "default", "protocol": proto, "dev": "eth0"}])
            self.assertEqual(out[0]["origin"], "automatic", proto)
            self.assertFalse(out[0]["handAdded"], proto)

    def test_a_missing_protocol_is_its_own_answer(self):
        # **The correction.** This used to assert `handAdded` is true for a route with no protocol,
        # with a comment claiming those routes had "no other record". They do: wg-quick installs them
        # from the peer's AllowedIPs, and on 2026-08-17 the four wg0 routes on gw-01.dev were measured
        # to equal that list exactly. Four of the six flagged routes were false positives.
        #
        # "The kernel did not say who put this here" and "a person put this here and did not write it
        # down" call for different next steps, and only one of them is a finding against anybody.
        out = hp._routes_from_json([{"dst": "10.254.0.0/16", "dev": "wg0"}])
        self.assertEqual(out[0]["origin"], "unstated")
        self.assertFalse(out[0]["handAdded"])

    def test_boot_counts_as_a_person_too(self):
        # `ip route add` with no protocol given records `boot`. Same author as `static`.
        out = hp._routes_from_json([{"dst": "10.9.0.0/16", "protocol": "boot", "dev": "eth0"}])
        self.assertEqual(out[0]["origin"], "static")

    def test_survives_a_row_it_does_not_understand(self):
        # `ip -json` is not a stable API. A row that is not an object must not take the whole
        # observation down — the alternative is a host reporting no routes because one line was odd.
        out = hp._routes_from_json(["nonsense", {"dst": "10.0.0.0/8", "protocol": "kernel"}])
        self.assertEqual(len(out), 1)

    def test_orders_so_two_reads_can_be_compared(self):
        rows = [{"dst": "10.2.0.0/16", "table": "main"}, {"dst": "10.1.0.0/16", "table": "main"}]
        self.assertEqual([r["dst"] for r in hp._routes_from_json(rows)], ["10.1.0.0/16", "10.2.0.0/16"])

class RouteRefusals(unittest.TestCase):
    """What the route applier will not run, and why each one is a class rather than a taste.

    Every refusal here is a route whose failure removes the way back rather than merely breaking
    traffic. The declaration is reviewed by one person and approved by a second, and that is still not
    a reason for this code to run whatever it is handed -- the two-person rule protects against a bad
    decision, not against a typo in a next hop.
    """

    def test_refuses_the_default_route(self):
        # The host's only path to everything it has no specific route for. Replacing it is the
        # fastest way to lose a machine, and the timer would take sixty seconds to notice.
        for dst in ("default", "0.0.0.0/0", "::/0"):
            why = hp._route_refusal({"dst": dst, "via": "10.0.0.1"}, relay="")
            self.assertIsNotNone(why, dst)
            self.assertIn("default route", why)

    def test_refuses_a_prefix_wider_than_slash_eight(self):
        # The same route wearing a different mask. `/1` is not a default route by name and is one in
        # effect, which is exactly the shape a check on the word `default` alone would let through.
        why = hp._route_refusal({"dst": "0.0.0.0/1", "via": "10.0.0.1"}, relay="")
        self.assertIsNotNone(why)
        self.assertIn("wider than", why)
        # And the boundary is inclusive on the safe side, so a legitimate /8 is allowed.
        self.assertIsNone(hp._route_refusal({"dst": "10.0.0.0/8", "via": "10.0.0.1"}, relay=""))

    def test_refuses_a_table_other_than_main(self):
        # A non-main table is consulted only if a rule points at it. Writing to one nothing references
        # is a no-op that looks like control, and looking like control is worse than doing nothing.
        why = hp._route_refusal({"dst": "10.9.0.0/16", "via": "10.0.0.1", "table": "100"}, relay="")
        self.assertIsNotNone(why)
        self.assertIn("not main", why)

    def test_refuses_a_route_with_neither_next_hop_nor_interface(self):
        why = hp._route_refusal({"dst": "10.9.0.0/16"}, relay="")
        self.assertIsNotNone(why)
        self.assertIn("neither", why)

    def test_refuses_a_route_that_covers_the_relay(self):
        # **The one that matters most.** Replacing the route carrying the heartbeat removes the
        # mechanism that would undo it. The deadline would still fire, but recovering in sixty seconds
        # is a worse outcome than declining to act.
        why = hp._route_refusal({"dst": "10.17.0.0/16", "via": "10.17.0.10"}, relay="10.17.0.1")
        self.assertIsNotNone(why)
        self.assertIn("relay", why)
        # A route that does not cover it is fine, even on the same host.
        self.assertIsNone(hp._route_refusal({"dst": "10.17.128.0/18", "via": "10.17.0.10"}, relay="10.17.0.1"))

    def test_a_relay_named_by_dns_is_not_treated_as_an_address(self):
        # `ipaddress` raises on a hostname. Letting that propagate would refuse every route on a
        # deployment that names its relay by DNS; resolving it here would make a refusal depend on a
        # lookup that can answer differently than the kernel's routing does.
        self.assertIsNone(hp._route_refusal({"dst": "10.9.0.0/16", "via": "10.0.0.1"}, relay="gw.dev.internal"))

    def test_refuses_something_that_is_not_a_network(self):
        why = hp._route_refusal({"dst": "not-a-network", "via": "10.0.0.1"}, relay="")
        self.assertIsNotNone(why)
        self.assertIn("not a network", why)

    def test_allows_the_route_this_fleet_would_actually_declare(self):
        # The known positive. Without it every assertion above would pass on a function that refuses
        # everything, which is the failure mode of a safety check nobody exercised from the other side.
        self.assertIsNone(hp._route_refusal(
            {"dst": "10.17.128.0/18", "via": "10.17.0.10", "dev": "enp8s0"}, relay="10.254.0.6"))


class RouteManagementGuard(unittest.TestCase):
    """Routes the agent refuses because the heartbeat cannot see the path they would break.

    ## The gap

    A successful heartbeat proves the **relay** path survived. Management arrives from somewhere else --
    on this fleet, WARP at 10.254.0.0/16 and the gateway backbone at 10.255.0.0/16 -- so a route that
    redirects those ranges locks every operator out of the host and then **confirms cleanly**. The
    deadline exists and has nothing to notice.

    `mustContain` is this same protection on the ruleset side. It is a refusal there and a refusal here
    for the same reason: a route is applied in one syscall, and by the time you could look, the path you
    would look through is gone.
    """

    GUARD = ["10.254.0.0/16", "10.255.0.0/16", "203.0.113.25/32"]

    def test_refuses_a_route_that_is_the_management_range(self):
        why = hp._route_refusal(
            {"dst": "10.254.0.0/16", "via": "10.17.0.99"}, relay="", guard=self.GUARD)
        self.assertIsNotNone(why)
        self.assertIn("management range", why)
        self.assertIn("heartbeat", why)

    def test_refuses_a_route_wider_than_the_management_range(self):
        # `10.0.0.0/8` swallows 10.254.0.0/16. Containment in the other direction only -- asking whether
        # the guard contains the route -- would let this straight through.
        why = hp._route_refusal({"dst": "10.0.0.0/8", "via": "10.17.0.99"}, relay="", guard=self.GUARD)
        self.assertIsNotNone(why)
        self.assertIn("management range", why)

    def test_refuses_a_route_narrower_than_the_management_range(self):
        # And the other half of "overlap, not containment": a /24 inside the management range redirects
        # part of it. Everybody whose address falls in that quarter loses the host.
        why = hp._route_refusal({"dst": "10.254.7.0/24", "via": "10.17.0.99"}, relay="", guard=self.GUARD)
        self.assertIsNotNone(why)
        self.assertIn("management range", why)

    def test_refuses_a_route_covering_the_operators_public_address(self):
        # The baseline carries a /32 for the operator's direct public egress. A route over it is the
        # same failure with one address in it.
        why = hp._route_refusal(
            {"dst": "203.0.113.0/24", "via": "10.17.0.99"}, relay="", guard=self.GUARD)
        self.assertIsNotNone(why)

    def test_allows_a_route_that_touches_no_management_range(self):
        # The known positive. Without it every assertion above would pass against a function that
        # refuses everything -- which is how a safety check nobody exercised from the other side ends up
        # blocking the feature it was meant to protect.
        self.assertIsNone(hp._route_refusal(
            {"dst": "10.17.128.0/18", "via": "10.17.0.10", "dev": "enp8s0"}, relay="", guard=self.GUARD))

    def test_an_unparseable_guard_entry_does_not_block_every_route(self):
        # A typo in the baseline is itself a finding, and refusing on it would let one bad character stop
        # the whole routing half. The manifest that carried it was reviewed by two people.
        self.assertIsNone(hp._route_refusal(
            {"dst": "10.17.128.0/18", "via": "10.17.0.10"}, relay="", guard=["not-a-cidr"]))

    def test_a_v6_guard_entry_is_not_compared_against_a_v4_route(self):
        # Different families never overlap, and `ipaddress` raises rather than returning False when they
        # are compared. Letting that propagate would refuse every route on a dual-stack baseline.
        self.assertIsNone(hp._route_refusal(
            {"dst": "10.17.128.0/18", "via": "10.17.0.10"}, relay="", guard=["fd00::/8"]))

    def test_no_guard_means_no_guard_refusals(self):
        # The parameter defaults to empty so the other refusal tests read what they mean. The manifest
        # path does **not** default: a generation that ships routes with no `routeGuard` is refused, in
        # `apply_host` -- "nothing is protected" and "we did not say" are different statements.
        self.assertIsNone(hp._route_refusal({"dst": "10.254.0.0/16", "via": "10.17.0.99"}, relay=""))

    def test_the_guard_reaches_the_planner(self):
        # Threading is the part that silently fails: a refusal that exists and is never passed the guard
        # is a check that always says yes. This is the seam.
        to_write, prior, refused = hp.plan_routes(
            [{"dst": "10.254.0.0/16", "via": "10.17.0.99"}], [], relay="", guard=self.GUARD)
        self.assertEqual(to_write, [])
        self.assertEqual(len(refused), 1)
        self.assertIn("management range", refused[0][1])

    def test_the_guard_reaches_the_applier(self):
        calls = []
        real = hp._ip_route
        hp._ip_route = lambda args: (calls.append(list(args)) or (0, ""))
        try:
            ok, restore, detail = hp.apply_routes(
                [{"dst": "10.255.0.0/16", "via": "10.17.0.99"}], [], relay="", guard=self.GUARD)
        finally:
            hp._ip_route = real
        self.assertFalse(ok)
        self.assertEqual(calls, [], "it ran `ip route` on a refused route")
        self.assertIn("management range", detail)


class RoutePlan(unittest.TestCase):
    """What gets written, and what each destination held first."""

    LIVE = [
        {"dst": "10.17.0.0/16", "via": "", "dev": "enp8s0", "proto": "kernel", "table": "main"},
        {"dst": "10.17.128.0/18", "via": "10.17.0.10", "dev": "enp8s0", "proto": "static", "table": "main"},
    ]

    def test_writes_nothing_when_the_route_is_already_there(self):
        # Every generation re-applies, so the common case is that nothing needs doing. A plan that
        # rewrote an identical route every time would make the journal unreadable and each write is a
        # chance to fail.
        spec = {"dst": "10.17.128.0/18", "via": "10.17.0.10", "dev": "enp8s0"}
        to_write, prior, refused = hp.plan_routes([spec], self.LIVE, relay="")
        self.assertEqual(to_write, [])
        self.assertEqual(refused, [])

    def test_writes_a_route_that_is_missing(self):
        spec = {"dst": "10.17.192.0/18", "via": "10.17.0.10", "dev": "enp8s0"}
        to_write, prior, refused = hp.plan_routes([spec], self.LIVE, relay="")
        self.assertEqual(to_write, [spec])
        # Nothing held that destination, so rollback restores by deleting.
        self.assertEqual(prior, [None])

    def test_records_the_route_it_is_about_to_overwrite(self):
        # The case `replace` exists for: a destination pointing at the wrong next hop. What was there
        # has to be recorded or rollback restores a guess.
        spec = {"dst": "10.17.128.0/18", "via": "10.17.0.99", "dev": "enp8s0"}
        to_write, prior, refused = hp.plan_routes([spec], self.LIVE, relay="")
        self.assertEqual(to_write, [spec])
        self.assertEqual(prior[0]["via"], "10.17.0.10")

    def test_a_refused_route_is_reported_and_nothing_is_written(self):
        # Refusing is a refused generation, not a warning: a route the policy declared and this agent
        # declined to write is a difference between what was approved and what is running.
        good = {"dst": "10.9.0.0/16", "via": "10.0.0.1"}
        to_write, prior, refused = hp.plan_routes([good, {"dst": "default", "via": "10.0.0.1"}], self.LIVE, relay="")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0][0], "default")

    def test_survives_a_declaration_that_is_not_an_object(self):
        to_write, prior, refused = hp.plan_routes(["nonsense"], self.LIVE, relay="")
        self.assertEqual(to_write, [])
        self.assertEqual(len(refused), 1)

    def test_builds_ip_arguments_in_a_fixed_order(self):
        # Two reads of the same route have to produce the same command, or a journal cannot be compared
        # against itself.
        self.assertEqual(
            hp._route_args({"dst": "10.9.0.0/16", "via": "10.0.0.1", "dev": "eth0"}),
            ["10.9.0.0/16", "via", "10.0.0.1", "dev", "eth0"],
        )


class RouteApplyAndRestore(unittest.TestCase):
    """Writing and undoing, with `ip` replaced by a recorder."""

    def setUp(self):
        self.calls = []
        self._real = hp._ip_route
        hp._ip_route = lambda args: (self.calls.append(list(args)) or (0, ""))

    def tearDown(self):
        hp._ip_route = self._real

    def test_uses_replace_so_a_repeat_apply_is_a_no_op(self):
        ok, restore, detail = hp.apply_routes(
            [{"dst": "10.9.0.0/16", "via": "10.0.0.1"}], [], relay="")
        self.assertTrue(ok, detail)
        self.assertEqual(self.calls, [["replace", "10.9.0.0/16", "via", "10.0.0.1"]])

    def test_restores_by_deleting_what_it_added(self):
        # The destination was empty, so putting it back means removing it. Restoring "nothing" any
        # other way would leave the route in place while the state file said rolled-back.
        ok, restore, _ = hp.apply_routes([{"dst": "10.9.0.0/16", "via": "10.0.0.1"}], [], relay="")
        self.calls.clear()
        ok, detail = hp._restore_routes(restore)
        self.assertTrue(ok, detail)
        self.assertEqual(self.calls, [["del", "10.9.0.0/16", "via", "10.0.0.1"]])

    def test_restores_the_route_it_overwrote(self):
        live = [{"dst": "10.9.0.0/16", "via": "10.0.0.1", "dev": "eth0", "proto": "static", "table": "main"}]
        ok, restore, _ = hp.apply_routes([{"dst": "10.9.0.0/16", "via": "10.0.0.2"}], live, relay="")
        self.calls.clear()
        hp._restore_routes(restore)
        self.assertEqual(self.calls, [["replace", "10.9.0.0/16", "via", "10.0.0.1", "dev", "eth0"]])

    def test_undoes_in_reverse_order(self):
        # Later routes can depend on earlier ones being present. Undoing forwards can remove the next
        # hop a subsequent restore needs.
        ok, restore, _ = hp.apply_routes(
            [{"dst": "10.9.0.0/16", "via": "10.0.0.1"}, {"dst": "10.8.0.0/16", "via": "10.0.0.1"}], [], relay="")
        self.calls.clear()
        hp._restore_routes(restore)
        self.assertEqual([c[1] for c in self.calls], ["10.8.0.0/16", "10.9.0.0/16"])

    def test_a_partial_apply_reports_only_what_it_wrote(self):
        # The second write fails. Rollback must undo the first and must not claim the second, which was
        # never made -- a restore list longer than what happened deletes a route somebody else owns.
        seen = []

        def flaky(args):
            seen.append(list(args))
            return (0, "") if len(seen) == 1 else (2, "RTNETLINK answers: Network is unreachable")

        hp._ip_route = flaky
        ok, restore, detail = hp.apply_routes(
            [{"dst": "10.9.0.0/16", "via": "10.0.0.1"}, {"dst": "10.8.0.0/16", "via": "10.0.0.9"}], [], relay="")
        self.assertFalse(ok)
        self.assertIn("unreachable", detail)
        self.assertEqual(len(restore), 1)
        self.assertEqual(restore[0]["spec"]["dst"], "10.9.0.0/16")

    def test_an_absent_route_is_a_successful_delete(self):
        # `ip route del` on something already gone is the desired end state. Treating it as a failure
        # would leave the whole rollback in `rollback-failed` and retrying forever.
        hp._ip_route = lambda args: (2, "RTNETLINK answers: No such process")
        ok, detail = hp._restore_routes([{"spec": {"dst": "10.9.0.0/16"}, "before": None}])
        self.assertTrue(ok, detail)

    def test_a_failed_restore_says_so(self):
        hp._ip_route = lambda args: (2, "RTNETLINK answers: Network is unreachable")
        ok, detail = hp._restore_routes([{"spec": {"dst": "10.9.0.0/16"}, "before": None}])
        self.assertFalse(ok)
        self.assertIn("incomplete", detail)

    def test_nothing_to_restore_is_a_success(self):
        ok, detail = hp._restore_routes([])
        self.assertTrue(ok)
        self.assertEqual(self.calls, [])

    def test_never_deletes_a_route_it_did_not_write(self):
        # The owner boundary, as behaviour. heliopause installs what it owns and removes nothing else;
        # a rollback that swept the table would take out wg-quick's routes and the kernel's.
        live = [{"dst": "10.7.0.0/16", "via": "10.0.0.5", "dev": "wg0", "proto": "", "table": "main"}]
        ok, restore, _ = hp.apply_routes([{"dst": "10.9.0.0/16", "via": "10.0.0.1"}], live, relay="")
        self.calls.clear()
        hp._restore_routes(restore)
        touched = [c[1] for c in self.calls]
        self.assertNotIn("10.7.0.0/16", touched)

class TestObservationLossIsNotIntrusion(unittest.TestCase):
    """Losing sight of the table and seeing somebody touch it are different facts.

    They were the same fact until 2026-09-03. `take_events` appends a marker when the monitor buffer
    overflows, and that marker carried our own table name with `byAgent: False` -- exactly the shape
    `unauthorised_events` matches. So a burst large enough to overflow (somebody reloading the whole
    ruleset; `systemctl disable --now firewalld` does it) was reported as one unauthorised change to
    a table that, on the host where stardust asked about it, did not exist.
    """

    def setUp(self):
        with hp._events_lock:
            hp._events.clear()
            hp._events_dropped = 0

    tearDown = setUp

    def test_overflow_marker_is_not_counted_as_an_intruder(self):
        with hp._events_lock:
            hp._events_dropped = 41
        events = hp.take_events()
        self.assertEqual(hp.unauthorised_events(events), [])
        lost = hp.observation_lost(events)
        self.assertEqual(len(lost), 1)
        self.assertEqual(lost[0]["dropped"], 41)

    def test_a_real_third_party_change_is_still_an_intruder(self):
        # The known positive. Without it the fix above could be "count nothing" and pass.
        with hp._events_lock:
            hp._events.append({
                "at": "2026-09-03T00:00:00Z",
                "table": f"{hp.TABLE_FAMILY} {hp.TABLE_NAME}",
                "raw": "add rule inet heliopause input accept",
                "pid": 999, "process": "nft", "byAgent": False,
            })
        events = hp.take_events()
        self.assertEqual(len(hp.unauthorised_events(events)), 1)
        self.assertEqual(hp.observation_lost(events), [])

    def test_our_own_change_is_neither(self):
        with hp._events_lock:
            hp._events.append({
                "at": "2026-09-03T00:00:00Z",
                "table": f"{hp.TABLE_FAMILY} {hp.TABLE_NAME}",
                "raw": "add table inet heliopause",
                "pid": 1, "process": "python3", "byAgent": True,
            })
        events = hp.take_events()
        self.assertEqual(hp.unauthorised_events(events), [])
        self.assertEqual(hp.observation_lost(events), [])


class TestAgentBuildIdentity(unittest.TestCase):
    """`AGENT_VERSION` is what a person says the build is; this is what the build *is*.

    Measured 2026-09-03: adding `HELIOPAUSE_K8S_PEER_NAMESPACES` moved neither `AGENT_VERSION` nor
    `SCHEMA_VERSION` -- there was no reason for either to move -- and the applier ran a build without
    that support while reporting identical values to one with it. The refusal that followed was
    diagnosable only from the host's journal.
    """

    def test_the_build_id_is_the_digest_of_this_file(self):
        import hashlib
        with open(hp.__file__, "rb") as fh:
            expected = hashlib.sha256(fh.read()).hexdigest()[:12]
        self.assertEqual(hp.AGENT_BUILD, expected)
        # Twelve characters, the length `src/build-id.ts` truncates to, so the two columns an
        # operator compares are the same shape.
        self.assertEqual(len(hp.AGENT_BUILD), 12)

    def test_it_travels_on_the_heartbeat(self):
        beat = hp.build_heartbeat(dict(hp._EMPTY_STATE))
        self.assertEqual(beat["agentBuild"], hp.AGENT_BUILD)
        self.assertEqual(beat["agentVersion"], hp.AGENT_VERSION)
        # No refusal to report, so the field is absent rather than null -- an older relay sees the
        # shape it already knows.
        self.assertNotIn("lastRefusal", beat)

    def test_a_refusal_travels_and_is_bounded(self):
        st = dict(hp._EMPTY_STATE)
        st["lastRefusal"] = {"generation": "gen9", "reason": "x" * 900, "at": "2026-09-03T00:00:00Z"}
        beat = hp.build_heartbeat(st)
        self.assertEqual(beat["lastRefusal"]["generation"], "gen9")


class TestRelayRequestDeadline(unittest.TestCase):
    """`HTTP_TIMEOUT_SEC` bounds the whole exchange, not each socket operation.

    `HTTPSConnection(timeout=…)` sets the socket timeout, which Python applies to **each** call: a
    relay answering one byte at a time resets it forever. That number is load-bearing arithmetic —
    `NFT_CONFIRM_MIN_SEC` is derived from `2 * HTTP_TIMEOUT_SEC` on the stated grounds of "one failed
    HTTP attempt plus a short retry", and the heartbeat loop's own comment calls the rollback window
    during a hung request "the full HTTP timeout rather than an instant".

    The rollback is not at risk either way — it fires from a `threading.Timer` and the heartbeat
    holds no lock. What an unbounded attempt costs is the retry, and with it a confirm window that
    elapses while one attempt is still in flight: a host that would have confirmed on the second
    rolls back a ruleset that was fine.

    These drive `_remaining` rather than a socket, because a test that has to trickle real bytes for
    ten seconds is one nobody runs. `_remaining` is where the deadline becomes an error, and the
    call sites are pinned separately by reading the source — a socket whose timeout is never re-armed
    from the clock is the defect, and that is visible as an absence.
    """

    def test_remaining_counts_down_and_then_refuses(self):
        deadline = time.monotonic() + 5
        left = hp._remaining(deadline, "reading the response body")
        self.assertGreater(left, 0)
        self.assertLessEqual(left, 5)

    def test_an_elapsed_deadline_raises_rather_than_returning_zero(self):
        # A socket reads a timeout of zero as **non-blocking**, not as expired. Returning 0 here
        # would turn an exhausted deadline into a socket that never waits, which is a different
        # failure with a much worse message.
        with self.assertRaises(TimeoutError) as caught:
            hp._remaining(time.monotonic() - 1, "reading the response body")
        self.assertIn("reading the response body", str(caught.exception))
        self.assertIn(str(hp.HTTP_TIMEOUT_SEC), str(caught.exception))

    def test_the_relay_call_re_arms_the_socket_from_the_deadline(self):
        # The call sites, as an absence. One `read(MAX_ARTIFACT_BYTES)` is a single call that keeps
        # resetting the socket timeout internally — the body has to be read in pieces with the clock
        # consulted between them, or the deadline above bounds nothing that matters.
        source = pathlib.Path(hp.__file__).read_text()
        body = source[source.index("def relay_request("):source.index("def post_heartbeat(")]
        self.assertIn("deadline = time.monotonic() + HTTP_TIMEOUT_SEC", body)
        self.assertEqual(
            body.count("conn.sock.settimeout(_remaining(deadline"), 3,
            "the request, the status and the body read each have to re-arm from the deadline",
        )
        self.assertNotIn(
            "resp.read(MAX_ARTIFACT_BYTES)", body,
            "one unbounded read is the defect — the body is read in pieces",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
