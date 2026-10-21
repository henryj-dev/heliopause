# Rocky 10 persistent backend — development record

Status: implementation candidate; actual boot matrix, final regressions, final source-bound report,
review and merge are required before completion. No trial/production deployment is authorized.
Phase 8/9 kernel-only results remain separate and do not prove persistent boot recovery.

## Measured disposable environment

User authorized container-local QEMU installation and disposable guests. No KVM device exists;
QEMU 10.0.13 TCG uses q35,smm=off, CPU max, 2 vCPU/2 GiB per guest. Guest glibc reports
x86-64-v3 support. The development image is Rocky 10.2 build 20260525.0 x86_64:

https://download.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base-10.2-20260525.0.x86_64.qcow2

SHA256 `9fc9e9ff16888bb68ac39b0392e25c9c92684d50c85f1cce6ab549363bbc4b48`.
The official CHECKSUM detached signature verified against Rocky 10 release fingerprint
`FC226859C0860BF0DDB95B085B106C736FEDFC85`, independently checked at
https://www.rockylinux.org/resources/gpg-key-info. This is a development minor/build, not
an assertion about a future trial target.

Measured versions: kernel 6.12.0-211.16.1.el10_2.0.1.x86_64, NetworkManager/libnm
1.56.0-1.el10, systemd 257-23.el10_2.1.rocky.0.1, Python 3.12.13, iproute2
6.17.0-2.el10, wireguard-tools 1.0.20250521-2.el10, nftables 1.1.5-4.el10.
Official NM 1.56 settings/keyfile documentation is the contract reference:
https://networkmanager.dev/docs/api/1.56/settings-connection.html and
https://networkmanager.dev/docs/api/1.56/nm-settings-keyfile.html.
The installed version and individual active device UUIDs, rather than service presence alone,
establish NetworkManager ownership. The read-only preflight remains inventory only.

Gateway and peer use persistent guest disks. The peer also hosts separate client/workload
namespaces, independent verifier and real mTLS Manager. The peer survives gateway reboot.
Management, WireGuard underlay and client LAN have separate NICs over host-loopback QEMU
UDP pairs. Restricted slirp exposes only localhost SSH; no production bridge, PKI, policy,
kubeconfig or site data is attached. Serial console login was exercised independently of SSH.
Guest journald uses /var/log/journal on the guest disk. Host source uploads are not journal storage.

## Signed contract and ownership

`linux-wireguard-v1` retains its kernel-only meaning. New approved operation identity is
`networkmanager-wireguard-1.56-v1`; only measured daemon/libnm 1.56.0 is accepted. Backend
absence/version mismatch fails explicitly. Registry ownership and signed artifact include the
new driver, transaction-derived profile UUID and `bootPolicy=agent-confirmed-only`.
Other fields retain the restricted dedicated interface, IPv4 /32 address, explicit /32 routes,
MTU, port, peer public key/endpoint/allowed IPs and protected secret reference. No arbitrary
path, shell, hook, external profile adoption, default route or IPv6 operation is accepted.

The keyfile name is derived from UUID under /etc/NetworkManager/system-connections.
A random owner nonce is persisted before the first write and included in ownership metadata
and deterministic staging identity. Protected directory descriptors, no symlinks, exclusive
create/no-replace rename, root-owned 0600 file, content hash, disk/cache semantic comparison,
UUID/device activation and restricted kernel shape establish ownership. A foreign file,
loaded profile, route or device causes refusal and evidence preservation. Similar names never
permit adoption. Disk, NM cache and kernel are independent stores; no rename spans them.

The original private key is read only from the protected secret directory. NM necessarily
stores a second private-key copy in its root-owned 0600 keyfile. libnm comparison receives
expected material through stdin and has fixed diagnostics; no profile export, argv secret or
raw backend stderr enters Registry, authorization or ordinary Agent logs. Undo uses the
persisted commitment and can remove owned objects even if the original secret is gone.
Boot restoration requires the original protected secret to remain valid.

## Crash and boot state table

All profiles have `autoconnect=false`, including confirmed profiles. Confirmation grants
Agent-only boot activation by durably storing original signed approval and signed confirm
with independent verifier evidence. There is no second autoconnect-bit store to synchronize.
A process restart in the same boot does not reactivate a confirmed profile.

| Crash point | Durable state / possible NM-kernel state | Next boot behavior |
|---|---|---|
| Before undo | No admitted mutation; foreign objects untouched | No restore authority |
| Undo saved, profile absent | Prepared owner/commitment; no profile | Roll back unconfirmed row; verify absence |
| Profile created, not activated | Root 0600 file, autoconnect false; cache may be absent | No NM autoactivation; owned removal and fsync |
| During activation | Applying row; cache/kernel can be partial | Cancel/remove owned UUID; ambiguous cancellation stays rollback-failed |
| Verification/confirm wait | Unconfirmed row and inactive-at-boot file | Undo before new execution; historical packets grant no boot permission |
| Confirm persistence boundary | Either old unconfirmed row or fully durable confirmed signed evidence | Old state rolls back; confirmed state gets one bounded Agent restore attempt |
| During rollback | Rolling-back/rollback-failed row; partial independent stores | Retry owned undo; preserve foreign drift and failure debt |
| Objects removed, terminal save pending | Prior unconfirmed row; objects absent | Reverify absence and directory durability, then terminal report |

Complete staging files are removable only with exact expected hash. Incomplete staging is
explicit recovery debt, never silently discarded. Absent profile deletion still fsyncs its
directory. NM activation is asynchronous: lack of a kernel link alone does not prove cancellation.
The driver cancels an active/activating UUID, or requires a changed NM bus owner before
claiming an uncertain queued request cannot finish. Foreign changes are preserved.

## Service integration and current status

The opt-in NM drop-in is installed beside the existing integrated Agent drop-in. It adds
Wants/After=NetworkManager and only the required keyfile directory to writable paths; it
adds no capabilities. Wants permits firewall recovery even if NM fails. Existing firewall
boot restore is attempted before the network worker; its failure is caught independently
so network recovery still runs. Network restore failure cannot suppress the earlier firewall
attempt. Unit configuration is not itself proof of measured boot ordering.

The existing mailbox worker and common writer gate execute restore; no independent network
writer bypasses heartbeat/watchdog/discovery arbitration. Synchronous startup recovery never
iterates confirmed undo debts. Worker restore has shared 60-second activation/90-second total
recovery budgets; tick retries one confirmed undo debt with five seconds, never reactivating
in the same boot. Admission is blocked while recovery is unresolved. Capacity is checked
before saving restore undo and before mutation; successful plans compact to a hash.

Confirmed terminal history/settlement/replay identity is preserved across boot. Restoration
separately reports restored/degraded and currentConnectivity=unknown. Kernel matching is
reported independently; only new external packets can establish current management and
bidirectional forwarding. Old verifier proof is never fresh reachability evidence. Failed
restoration preserves the profile, signed evidence and diagnostics, undoes owned boot
activation where possible, and stops new activation until a new boot. An administrator must
inspect ownership/drift and restore required secret/profile prerequisites; no force-unlock,
ledger reset, automatic reacceptance or general confirmed-profile deletion is provided.

## Validation and remaining gates

Prototype runs use dirty development source and are excluded from final source-bound counts.
Real Agent signed apply reached awaiting-verification; independent forward/reverse/management
packets were observed. A delayed confirm expired and the Agent rolled back and settled through
real mTLS. This is useful failure evidence, not a successful confirmed-boot test.

Required final report must distinguish implementation, measured VM results, hosted-container
regressions and documentation. The thirteen actual boot scenarios, certificate rotation and
revocation exercises, bounded evidence archive/ledger replacement, prolonged stability,
independent final review and green main merge remain completion/trial gates. No long-term
readiness is claimed without safe archive/replacement tooling. Never prune replay ledgers or
remove an existing confirmed object to make another test fit.
