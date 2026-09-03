# Agent auto-update — design

Today a new agent reaches a host by hand: copy the file, restart the unit, check that the process
actually restarted. That last step is not optional and is easy to skip — a deployment once left the
file replaced and the old process running, with `systemctl is-active` reporting `active` the whole
time. Eight hosts is already enough for the manual path to drift silently; the fleet carried two
different builds under one version string until `AGENT_BUILD` made them distinguishable.

This document is the design for automating it. The conclusion is narrower than the question:
**agents yes, relays no**, and the code artifact must not be signed by the key that signs rules.

## What already exists

Almost every part is built, because policy distribution needed the same guarantees.

| Need | Where it lives |
|---|---|
| Signed artifact envelope — Ed25519, key-set trust, SPKI-sha256 key ids, TTL bounds, replay records | `verify_artifact_envelope` in `agent/heliopause-pull.py` |
| Two-person approval with OTP | `heliopause-publish --propose` → `heliopause-approve --approve` → `--push` |
| Authenticated transport, both hops mTLS, relay certificate pinned at the agent | `POST /publish`, `GET /artifact` in `src/relay.ts` |
| Staged rollout that fails closed | `src/rollout.ts` — `canary` → `general` → `gateway` |
| Build identity and refusal reporting in the fleet view | `AGENT_BUILD`, `lastRefusal` |
| Durable commitment written before the change, recovered after a restart | `_persist_commitment` / `recover_commitment` |

The staging property is worth quoting, because it is exactly what a bad build needs:

> A generation does not reach every host at once. Hosts are assigned a stage, and a stage only opens
> once every host in the stages before it is confirmed at that same generation. The value of this is
> entirely in the failure case: a policy that locks hosts out locks out the canary, the canary never
> confirms, and the rest of the fleet never receives it.

Substitute "a build that crashes on startup" for "a policy that locks hosts out" and the sentence
still holds. `gateway` being last matters too — the hosts that carry the relays update after everyone
who depends on them has already proven the build.

Size is not a constraint: `MAX_SIGNED_PAYLOAD_BYTES` is 5 MiB against an agent of ~250 KB.

## Decision 1 — code artifacts require an offline key

**The online manager key must never be able to sign code.**

Today the worst that key can do is push a ruleset. That is bad and bounded: it can sever a host, and
the host's own rollback undoes it. Signing code changes the class of the failure — the same key would
be able to run arbitrary code as root on every host, and nothing downstream can undo that, because
the thing that would undo it is what was just replaced. A key with a seven-day authorization lifetime
that lives in the manager process should not hold that power.

The trust machinery already distinguishes rings and enforces them per artifact:

```python
required_class = "break-glass" if mode == "break-glass" else "manager"
if trusted[0] != required_class:
    raise ValueError(f"{mode} authorization requires a {required_class} trust key")
```

So the rule is a two-line extension, not a new mechanism: a code artifact requires a key from an
offline ring. Whether that is the existing `break-glass` ring or a third `code` ring is an open
question below.

The cost is that a code release takes an offline key out once. Code releases are not a daily event,
and the fleet keeps auto-updating from that one signature — the human step is per release, not per
host, which is precisely the part that does not scale today.

## Decision 2 — a separate endpoint, not a new field

The signed payload is a closed schema:

```python
_exact_keys(payload, ["version", "target", "planHash", ..., "workload"], "signed artifact payload")
```

An agent rejects a payload carrying a field it does not know. That is the correct behaviour and it
must not be weakened — but it means adding a field to the existing artifact would make **every
currently deployed agent refuse every generation**, which is the worst possible way to ship an
update mechanism.

A separate endpoint (`GET /agent-build` alongside `GET /artifact`) avoids the problem entirely:
agents that do not know about it never call it, and the ones that do begin auto-updating. No schema
break, no flag day. The first build carrying the client is installed by hand — once, and never again.

## Decision 3 — the agent does not update itself

The unit denies the agent write access to its own source, and that property is kept:

```ini
ExecStart=/usr/bin/python3 /opt/heliopause/agent/heliopause-pull.py
ProtectSystem=strict
ReadWritePaths=/var/lib/heliopause-agent
```

The agent's job is to **fetch, verify, and stage** — write the verified candidate into its own state
directory and record what it staged. A separate unit with `ReadWritePaths=/opt/heliopause` installs
it. The privilege to fetch and the privilege to install stay in different processes, so a compromise
of the network-facing one does not directly become code execution from disk.

The installer should verify the candidate compiles before swapping it in (`python3 -m py_compile` is
cheap and catches the whole class of "the file arrived truncated"). That is a gate, not a guarantee —
see the next decision for what catches the rest.

## Decision 4 — rollback needs an actor outside the agent, and systemd's failure path cannot be it

This is the part with no existing analogue, and the reason it is hard is structural: the ruleset
rollback works because the agent is alive to perform it. For a code update, the thing that might be
broken is the code that would perform the rollback. `recover_commitment()` runs inside the new agent;
a new agent that dies during import never reaches it.

The obvious hook does not work either. The unit disables restart rate limiting on purpose:

```ini
Restart=always
StartLimitIntervalSec=0
```

The unit comment explains why, and the reasoning is sound — a crash-looping firewall agent is a
better failure than one pinned in `failed` with an unconfirmed ruleset and no code left running to
roll it back. But the consequence is that the unit **never enters `failed`**, so `OnFailure=` never
fires. A crash-looping agent is invisible to systemd's failure path by construction.

So liveness must be judged on evidence rather than unit state. The proposed shape:

- The installer records the previous file and the time of the swap.
- A separate timer unit (`heliopause-agent-guard.timer`) checks one question: *has this host sent a
  heartbeat since the swap, within the window?* Heartbeat, not process liveness — a process that
  starts and then fails to reach the relay is exactly as broken as one that does not start.
- If not, restore the recorded previous file and restart. Then report it: a host that reverted a
  build is a fleet-visible fact, and `lastRefusal` is the precedent for how that reaches the view.

The guard must be small enough to read in one sitting and must not import the agent. It is the piece
that is trusted to work when the main program does not, so it earns its own test and its own review.

Note the ordering interaction: the guard's window must be longer than the rollout stage's confirm
window, or a host reverts a build that was merely slow.

## Decision 5 — relays stay manual

Auto-updating the relay is a worse trade than auto-updating agents:

- **Few hosts, high value each.** One relay per gateway. The manual cost is already low.
- **It is the channel.** The relay serves the artifacts. A relay that breaks itself takes down the
  path that would deliver its own fix, for every host behind it.
- **The blast radius is the VPC, not the host.** An agent that reverts affects one machine; a relay
  that fails affects everything behind it.

A gateway runs both units, so the agent there *could* act as the relay's guard — they would watch
each other. It is an appealing symmetry and it is deliberately not the recommendation: it couples two
units whose failure domains are currently independent, and the mechanism most needed at the moment of
failure is the one that should have the fewest moving parts.

Relays keep the manual path, with one addition worth making regardless of this design: the deploy
step should verify `ExecMainStartTimestamp` moved, not just that the unit is `active`. That check is
what caught a relay that had been replaced on disk but never restarted.

## Open questions

1. **Third ring or reuse `break-glass`?** A separate `code` ring keeps emergency rule authority and
   code authority distinct, at the cost of another key to hold and rotate. Reusing `break-glass` is
   simpler but conflates two very different powers under one key.
2. **Guard window.** Must exceed the confirm window; the exact value should come from measured
   heartbeat intervals rather than being picked.
3. **Revert of a revert.** If a host reverts and the fleet keeps offering the same build, the host
   loops. The guard should refuse a build it has already reverted, and say so.
4. **Enrolment interaction.** A host that has not yet been issued a certificate cannot fetch
   anything; the `heliopause-agent.path` unit already handles that ordering for the agent, and the
   installer must not run before it.

## What this does not change

The agent's read-only source, the closed payload schema, the two-person approval for rules, the
disabled restart limit, and the relay's manual deployment all stay as they are. The new code is one
artifact kind, one endpoint, one installer unit, and one guard.
