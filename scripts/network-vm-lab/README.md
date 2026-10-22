## Lifecycle observation tools

Current key policy, read-only inventory and full24-hour baseline procedure are in
[the lifecycle policy](../../docs/network-lifecycle-policy.md). Tool existence is not a completed
long-duration or key-rotation result. Baseline and fault/rotation runs have separate identities.
The baseline validates initial and subsequent Agent/Manager settlement agreement, including exact
terminal results, outbox and acknowledgments; frozen file hashes alone are insufficient. Its replay
inspection uses production read-only load and never initializes, repairs or recovers a journal.

## Persistent backend development (Phase 10)

The Phase 9 read-only collector below remains inventory only. The new implementation and
measured Rocky 10.2/NM 1.56.0 development environment are described in
[the Phase 10 record](../../docs/network-phase10-validation.md). Its required boot matrix
and final source-bound report are separate completion gates; this README does not grant
readiness from service presence or a prototype reboot.

New tools act only on explicitly marked disposable guests. VM creation remains an
explicit lab preparation step; preserve the verified image manifest, exact QEMU argv,
private disk ownership and serial-console evidence in the dedicated lab root:

- `guest_fixture.py` provisions lab credentials, production Agent/service installation and
  fixed peer/workload namespaces. It never applies or restores a gateway transaction profile.
- `verify.ts confirm|observe` runs on the independent peer. Confirm signs fresh bounded
  collector evidence, uses the production Manager mTLS API and delivers its signed envelope
  to the production Agent mailbox. Observe produces a separately signed current boot
  observation and never reuses old verifier proof.
- `boot_cycle.py --root LAB --mode graceful|power-cut --output NEW_REPORT --transaction TX --expected restored|rolled-back|degraded-unchanged|rollback-failed|inactive` is a boot primitive,
  not the thirteen-case suite. It refuses dirty source, mismatched deployed module hashes,
  unmarked guests or a foreign QEMU process. `--require-confirmed-forwarding` requires fresh
  external packet probes after the changed guest boot ID. Virtual SIGKILL power loss differs
  from host power failure; disk/controller/host power durability is not inferred.

Lab roots contain private test credentials and persistent guest disks; keep them private and
outside the repository. Reports are created 0600 and preserve failure evidence. Do not copy
keyfiles/profile exports into reports. Failed cases remain failures. Do not reset a used
journal, remove confirmed objects or prune Manager fences to recycle a case.

# Historical Phase 9 preparation record (superseded by Phase 10)

The following section records the pre-Phase10 state, not current support. At that time, the owner selected Rocky Linux10 on2026-10-20, could not confirm NetworkManager, and has no disposable VM available. Local `qemu-system-x86_64`, `limactl` and `virsh` are absent. This directory contains preparation inputs only. No VM was provisioned or rebooted, no persistent backend is implemented, and no boot report is claimed. Hosted container/kernel success is not Rocky/NetworkManager certification.

## Reproducible preparation checklist

1. Supply a disposable hypervisor with serial-console access and actual reboot/power-cycle control, isolated from operational bridges, credentials and data. Record its name/version, virtualization support and CPU architecture in a private copy of `environment.example.json`. Do not turn the example's null/false values into success evidence. On x86_64 verify Rocky10's x86-64-v3 CPU requirement; an ARM VM is a different target and must be recorded explicitly.
2. Select an exact Rocky10 minor/image build matching the intended trial target. Obtain it from the [official download tree](https://download.rockylinux.org/pub/rocky/10/) and verify the published checksum/signature with an independently trusted Rocky release key. Pin exact URL, build, architecture and SHA256 in the environment record. No image digest has been measured here; do not copy a rolling `latest` name into a final report without its resolved hash.
3. Prepare five disposable guests (gateway, fixed-peer, verifier, client, workload), or explicitly document equivalent peer/verifier namespaces that survive the gateway's real VM reboot. Use the four isolated networks in the example. They have no NAT/default external uplink or production bridge. Give each guest a serial console; the verifier's management NIC remains independent of the WireGuard data path. The container lab's reserved IPv4 layout can be reused inside these networks, after confirming no connection to the host's real networks. Do not attach a host management interface for convenience.
4. Install tools and dependencies into an offline base image or through a temporary build-only network. Remove that build uplink before fault testing. Record exact kernel, systemd, NetworkManager (if active), iproute2, WireGuard and Python/Node versions. Generate all Agent/Manager/verifier PKI and WG keys inside this lab; never mount operational PKI, policy, kubeconfig or Docker socket. Keep the replay journal on the guest's persistent disk, not a shared temporary host directory.
5. Read only the following information in the disposable guest. Keep interface/route evidence local; do not upload a whole machine configuration or profile secrets:

```sh
cat /etc/os-release
uname -r
ip -Version
wg --version
nmcli --version
systemctl is-active NetworkManager systemd-networkd
systemctl show heliopause-agent.service NetworkManager.service \
  -p ActiveState -p After -p Before -p Wants -p Requires \
  -p ProtectSystem -p ReadWritePaths -p CapabilityBoundingSet -p TimeoutStopUSec
nmcli -t -f DEVICE,TYPE,STATE device status
nmcli -t -f UUID,TYPE,DEVICE connection show --active
ip -j link show
ip -j -4 route show table main
cat /proc/sys/kernel/random/boot_id
```

These are a read-only checklist, not a collector that was run on a trial host. Do not use `nmcli --show-secrets`, `wg showconf`, `systemctl show ... Environment`, unrestricted unit/config dumps or private-key paths in report output. `nmcli` failure means unknown/unavailable, not proof that a different writer owns the device. Correlate active NM UUID/device with systemd-networkd/other owner through approved read-only inspection before choosing one backend. Record the management, endpoint-underlay and workload routes separately, and verify they cross guests.

6. Once actual NM ownership/version is known, choose exactly one persistence backend. The current `linux-wireguard-v1` stays kernel-only. A future NM capability requires a distinct approved artifact/driver identity, unique owned profile UUID, autoconnect policy, secret reference and protected files; it must refuse foreign profiles and unavailable backend rather than falling back. The official [keyfile reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-keyfile.html) and [settings reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html) are design sources, not measurements of the missing VM's version.
7. Before any backend writes, implement and review this boot invariant: unconfirmed profiles cannot auto-activate before Agent recovery. A durable per-profile undo/snapshot precedes persistence; confirmed activation permission is promoted only after explicit confirm. Recovery must still run when new execution is disabled. Order network recovery and existing firewall boot restore without stopping heartbeat/watchdogs; keep an independent console/verifier. The exact unit ordering and NM API must be proven on the selected installed version. No such unit/backend is installed by this PR.

The peer `monitor.py` records management/forward/reverse packets throughout a boot. A report
requires fresh post-recovery samples, bounded gaps, matching final peer boot identity and a
non-expired monitor. `fault_entry.py` freezes only at production durable event boundaries.
`faults.py` injects fixed reversible prerequisite faults under a unique fault ID in a marked
guest; it preserves root-only originals/hashes and never activates or undoes a transaction.
Only the production Agent performs subsequent restore/undo and authenticated settlement.

## Required boot evidence before Phase C completion

Run each of the13 handoff VM cases: confirmed restore+independent management/bidirectional workload, kill/reboot prepared/applying, awaiting-confirm reboot, rollback reboot, rollback-failed reboot, delayed/failed Agent startup, NM restart, profile corruption/missing/foreign change, missing/unsafe secret, firewall boot restore coexistence, execution disabled recovery, and delayed terminal settlement retry. Treat confirmed restore and current connectivity as separate results: old verifier proof is never fresh forwarding evidence.

For every case record exact sourceCommit/image hash/version, before/after guest boot ID, Agent PID, persistent profile UUID/ownership, journal/fence state, timestamped management loss/recovery, link/address/routes, heartbeat/discovery/watchdog, independently observed forward/reverse packets and preserved failure diagnostics. A new process PID without changed `/proc/sys/kernel/random/boot_id` is not a host reboot. Do not turn unavailable virtualization into a skipped successful report. The historical Phase9/container result remains `hostRebootVerified:false`; Phase10 actual VM evidence is a separate result.

Do not enable a persistence backend on a trial/operational host until these cases pass with its actual OS and network manager. This preparation changes no host or network.

## Executable read-only inventory

After provisioning the disposable guest, copy this checkout into it and run as an ordinary user:

```sh
python3 scripts/network-vm-lab/preflight.py --collect
```

It prints JSON to stdout and exits **2** while prerequisites remain blocked. This is an inventory, not a boot-test runner or an execution authorization. It never sets `backendSelected` or `hostRebootVerified` to a successful value. On a non-Linux host it reports `linux-guest-required` without running guest probes. It does not connect over SSH or install tools/services.

The collector reads only bounded `/etc/os-release` ID/version and the local boot ID, kernel/architecture, four fixed tool-version commands and three fixed service `is-active` queries. Each command has a three-second timeout and a 4KiB stdout cap; stderr and inherited environment settings are discarded. Only recognized version/state fields are included, never whole command output. No interface addresses, route contents, NM connection names/UUIDs, profile settings, environment dumps, private keys or secret paths are collected. Do not upload the report without inspecting it: boot ID and kernel/OS versions remain machine metadata.

Device/route ownership, service ordering/security properties and the independent management/underlay/workload paths remain the manual checklist above; an active NM service does not establish ownership of a particular interface. NM failure stays unknown. No backend is selected from service presence. This command does not establish VM isolation, x86-64-v3 availability, image authenticity, clock safety, current packet delivery or a host reboot. That historical missing-VM blocker was resolved for the measured Phase10 development lab. The collector itself still proves no boot result.

Run the isolated fixture suite with `python3 scripts/network-vm-lab/test_preflight.py`; `npm test` also invokes it. Inventory tests replace OS/file/probe boundaries and fail on escaped Popen/socket/file access. Probe-boundary tests launch only the local Python interpreter for timeout, output cap, invalid UTF-8 and environment/stderr handling; file tests use a private temporary directory. They do not run host ip/wg/systemctl or exercise a VM backend.
