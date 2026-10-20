# Rocky Linux 10 VM preparation — blocked, not a boot test runner

The owner selected Rocky Linux10 on2026-10-20, could not confirm NetworkManager, and has no disposable VM available. Local `qemu-system-x86_64`, `limactl` and `virsh` are absent. This directory contains preparation inputs only. No VM was provisioned or rebooted, no persistent backend is implemented, and no boot report is claimed. Hosted container/kernel success is not Rocky/NetworkManager certification.

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

## Required boot evidence before Phase C completion

Run each of the13 handoff VM cases: confirmed restore+independent management/bidirectional workload, kill/reboot prepared/applying, awaiting-confirm reboot, rollback reboot, rollback-failed reboot, delayed/failed Agent startup, NM restart, profile corruption/missing/foreign change, missing/unsafe secret, firewall boot restore coexistence, execution disabled recovery, and delayed terminal settlement retry. Treat confirmed restore and current connectivity as separate results: old verifier proof is never fresh forwarding evidence.

For every case record exact sourceCommit/image hash/version, before/after guest boot ID, Agent PID, persistent profile UUID/ownership, journal/fence state, timestamped management loss/recovery, link/address/routes, heartbeat/discovery/watchdog, independently observed forward/reverse packets and preserved failure diagnostics. A new process PID without changed `/proc/sys/kernel/random/boot_id` is not a host reboot. Do not turn unavailable virtualization into a skipped successful report. Current result remains `hostRebootVerified:false`.

Do not enable a persistence backend on a trial/operational host until these cases pass with its actual OS and network manager. This preparation changes no host or network.
