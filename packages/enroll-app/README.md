# Heliopause Enroll

Lives in the heliopause monorepo at **`packages/enroll-app/`** so it stays in
lockstep with the enrollment/pki CLIs it wraps. The repo root (two levels up
from this package) is where `bin/heliopause-*.ts` resolve, and `binDir` defaults
to it — derived from the crate's manifest dir at build time, so it is correct
whenever the app is built and run from within the monorepo checkout.

A minimal **Tauri v2** desktop app that gives operators a GUI to list pending
host-enrollment CSRs and approve/sign them — by **shelling out to the existing,
already-vetted heliopause Node CLIs**. It reimplements no crypto.

## Security model

- **The CA private key never leaves the machine.** The app only *invokes* the
  vetted `heliopause-pki` / `heliopause-enrollment` CLIs; it never reads, copies,
  or stores key material. Signing happens offline in `heliopause-pki.ts sign-csr`
  against the local `pki/` dir.
- **No shell plugin, no broad capability.** All process spawning happens inside
  Rust commands using `std::process::Command` with argument *vectors* — never a
  shell string, so there is no interpolation/injection surface. The webview is
  granted only `core:default`.
- **The OTP is entered per-approval and never stored.** It is passed only to the
  final `cert-upload` step and lives only in memory for that one call.
- **Fingerprint confirmation.** Each card shows the CSR's `csrSha256` (the SHA-256
  of the CSR DER) in a monospace field. The operator is expected to confirm this
  fingerprint out of band before clicking **Approve & Sign**. That same value is
  passed to `sign-csr --expect-sha256=…`, which recomputes the CSR digest and
  aborts if it does not match.

## What it wraps

With `cwd = binDir` (so the `bin/*.ts` scripts resolve) and `pkiDir` passed as an
absolute path. The enrollment CLI takes **the subcommand first**, then the manager
URL (an `https://` store triggers its remote path), then the request id:

1. **List pending:**
   `node bin/heliopause-enrollment.ts csr-list <managerUrl> --status=pending --json --pki=<pkiDir> --operator=<operator>`
2. **Approve & sign** (three sequential steps; temp files cleaned up on every exit path):
   1. `node bin/heliopause-enrollment.ts csr-export <managerUrl> <id> --out=<tmp>/<id>.csr --pki=<pkiDir> --operator=<operator>`
   2. `node bin/heliopause-pki.ts sign-csr <pkiDir> <tmp>/<id>.csr <tmp>/<id>.crt --name=<hostname> --expect-sha256=<csrSha256>`
   3. `node bin/heliopause-enrollment.ts cert-upload <managerUrl> <id> --cert=<tmp>/<id>.crt --ca-name=<caName> --pki=<pkiDir> --operator=<operator> --otp=<otp>`

If any step exits non-zero, the flow stops and the failing step's stderr is
surfaced in the UI (red).

## Configuration

Persisted to `config.json` in the Tauri app-data dir (created if missing).
Edit it via the gear button.

| Field        | Default                                        | Notes                                              |
| ------------ | ---------------------------------------------- | -------------------------------------------------- |
| `binDir`     | the monorepo root (two levels up from this package) | cwd for node; the checkout holding the bin/*.ts |
| `managerUrl` | *(empty — set in Settings)*                        | remote enrollment manager                          |
| `pkiDir`     | *(empty — set in Settings)* | absolute path to the deploy checkout's `pki/`; used as `--pki` and `sign-csr <caDir>`   |
| `operator`   | *(empty — set in Settings)*                                    |                                                    |
| `caName`     | *(empty — set in Settings)*                    |                                                    |
| `nodePath`   | `node`                                         |                                                    |

## Prerequisites

- **Rust** (via [rustup](https://rustup.rs)) and a working C toolchain — Tauri's
  platform prerequisites: <https://tauri.app/start/prerequisites/>
- **Node.js** (used both to run the Tauri CLI and, at runtime, to execute the
  `.ts` CLIs the app shells out to).
- A **heliopause checkout** at `binDir` (defaults to the monorepo root, two
  levels up from this package) containing the remote-capable `bin/*.ts` CLIs,
  plus a **PKI dir** at `pkiDir` (default
  the deploy checkout's `pki/`) holding the operator certs and
  the CA. The CA + operator certs live in the separate deploy checkout —
  correctly not tracked in this source tree.

## Build / run

```bash
npm install          # fetches @tauri-apps/cli and @tauri-apps/api
npm run tauri dev    # dev: launches the app with the static frontend in src/
npm run tauri build  # bundle a distributable app
```

There is no frontend bundler: `src/` is plain HTML/CSS/JS and is served directly
(`frontendDist` points at `../src`; `app.withGlobalTauri` exposes
`window.__TAURI__`).

## Project layout

```
packages/enroll-app/
├── package.json
├── README.md
├── .gitignore
├── src/                     # vanilla frontend (no framework, no bundler)
│   ├── index.html
│   ├── main.js
│   └── styles.css
└── src-tauri/
    ├── Cargo.toml
    ├── build.rs
    ├── tauri.conf.json
    ├── capabilities/
    │   └── default.json     # core:default only — no shell plugin
    ├── icons/               # placeholder icons + generator + README
    └── src/
        ├── main.rs          # binary entrypoint → lib::run()
        └── lib.rs           # Tauri commands: load/save config, list, approve+sign
```

## Icons

Icons are **not committed** (this repo forbids binary/NUL bytes in tracked files).
Generate them once before the first build:

```bash
python3 src-tauri/icons/generate_icons.py   # or: npx tauri icon path/to/logo.png
```

See `src-tauri/icons/README.md`.
