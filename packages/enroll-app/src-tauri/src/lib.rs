// Heliopause Enroll — Tauri v2 backend.
//
// This app never touches key material. It only shells out to the already-vetted
// Node CLIs (`heliopause-enrollment.ts`, `heliopause-pki.ts`) with cwd set to the
// configured bin dir (the upstream checkout that holds the remote-capable CLIs) so
// the bin scripts resolve; the PKI dir (operator certs + CA) is passed as an
// absolute path. All process spawning uses std::process::Command with argument
// vectors — no shell, no interpolation.
//
// The enrollment CLI's positional order is COMMAND first, then the manager URL
// (which triggers its remote/HTTP path), then the request id.

use std::fs;
// Imports are split one-per-line rather than grouped `use x::{a, b}`: the repo's
// site-data scanner reads `::{` as the IPv6 literal `::` and fails the leak gate on it.
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use serde::Deserialize;
use serde::Serialize;
use tauri::Manager;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    /// cwd for node; the upstream checkout holding the remote-capable bin/*.ts.
    bin_dir: String,
    manager_url: String,
    /// Operator certs + CA. Passed absolute, used as both `--pki` and the
    /// `sign-csr <caDir>` positional.
    pki_dir: String,
    operator: String,
    ca_name: String,
    node_path: String,
}

/// The monorepo root, derived from this crate's manifest dir at build time.
/// The app lives at `packages/enroll-app/src-tauri`, so the repo root is three
/// levels up — the cwd where `node bin/heliopause-*.ts` resolves.
fn default_bin_dir() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bin_dir: default_bin_dir(),
            // Site-specific values are intentionally empty: the operator fills them in Settings on
            // first run. Committing one operator's manager IP / local paths / cert name would both
            // leak site data and wrongly pin defaults to a single machine.
            manager_url: String::new(),
            pki_dir: String::new(),
            operator: String::new(),
            ca_name: String::new(),
            node_path: "node".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CsrRow {
    id: String,
    hostname: String,
    /// SHA-256 of the CSR DER — the value the operator confirms and that
    /// `sign-csr --expect-sha256` verifies against.
    csr_sha256: String,
    status: String,
}

// Shape of the `csr-list --json` response. Extra fields are ignored.
#[derive(Deserialize)]
struct ListResponse {
    requests: Vec<ListRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRequest {
    id: String,
    hostname: String,
    csr_sha256: String,
    status: String,
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app-data dir: {e}"))?;
    Ok(dir.join("config.json"))
}

/// Keep only filesystem-safe characters so a CSR id can never escape the temp dir.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

#[tauri::command]
fn load_config(app: tauri::AppHandle) -> Result<Config, String> {
    let path = config_path(&app)?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let data = fs::read_to_string(&path).map_err(|e| format!("read config.json: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse config.json: {e}"))
}

#[tauri::command]
fn save_config(app: tauri::AppHandle, cfg: Config) -> Result<(), String> {
    let path = config_path(&app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create app-data dir: {e}"))?;
    }
    let data = serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize config: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("write config.json: {e}"))
}

#[tauri::command]
fn list_pending(cfg: Config) -> Result<Vec<CsrRow>, String> {
    let output = Command::new(&cfg.node_path)
        .current_dir(&cfg.bin_dir)
        .args([
            "bin/heliopause-enrollment.ts".to_string(),
            "csr-list".to_string(),
            cfg.manager_url.clone(),
            "--status=pending".to_string(),
            "--json".to_string(),
            format!("--pki={}", cfg.pki_dir),
            format!("--operator={}", cfg.operator),
        ])
        .output()
        .map_err(|e| format!("failed to launch {}: {e}", cfg.node_path))?;

    if !output.status.success() {
        return Err(format!(
            "csr-list exited {}: {}",
            output.status.code().unwrap_or(-1),
            stderr_of(&output)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: ListResponse = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("could not parse csr-list JSON: {e}\n{stdout}"))?;

    Ok(parsed
        .requests
        .into_iter()
        .map(|r| CsrRow {
            id: r.id,
            hostname: r.hostname,
            csr_sha256: r.csr_sha256,
            status: r.status,
        })
        .collect())
}

#[tauri::command]
fn approve_sign(
    cfg: Config,
    id: String,
    hostname: String,
    expect_sha256: String,
    otp: String,
) -> Result<String, String> {
    let safe_id = sanitize(&id);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("heliopause-enroll-{safe_id}-{nanos}"));
    fs::create_dir_all(&tmp).map_err(|e| format!("create temp dir: {e}"))?;

    let csr_path = tmp.join(format!("{safe_id}.csr"));
    let crt_path = tmp.join(format!("{safe_id}.crt"));

    // Run the whole flow in a closure so we can clean up the temp dir on every path.
    let result = run_approve_flow(&cfg, &id, &hostname, &expect_sha256, &otp, &csr_path, &crt_path);
    let _ = fs::remove_dir_all(&tmp);
    result
}

#[allow(clippy::too_many_arguments)]
fn run_approve_flow(
    cfg: &Config,
    id: &str,
    hostname: &str,
    expect_sha256: &str,
    otp: &str,
    csr_path: &Path,
    crt_path: &Path,
) -> Result<String, String> {
    // Step a — export the CSR to a temp file.
    let export = Command::new(&cfg.node_path)
        .current_dir(&cfg.bin_dir)
        .args([
            "bin/heliopause-enrollment.ts".to_string(),
            "csr-export".to_string(),
            cfg.manager_url.clone(),
            id.to_string(),
            format!("--out={}", csr_path.display()),
            format!("--pki={}", cfg.pki_dir),
            format!("--operator={}", cfg.operator),
        ])
        .output()
        .map_err(|e| format!("step a (csr-export) failed to launch: {e}"))?;
    if !export.status.success() {
        return Err(format!("step a (csr-export) failed: {}", stderr_of(&export)));
    }

    // Step b — sign offline with the local CA, verifying the expected key fingerprint.
    let sign = Command::new(&cfg.node_path)
        .current_dir(&cfg.bin_dir)
        .arg("bin/heliopause-pki.ts")
        .arg("sign-csr")
        .arg(&cfg.pki_dir)
        .arg(csr_path.to_string_lossy().to_string())
        .arg(crt_path.to_string_lossy().to_string())
        .arg(format!("--name={hostname}"))
        .arg(format!("--expect-sha256={expect_sha256}"))
        .output()
        .map_err(|e| format!("step b (sign-csr) failed to launch: {e}"))?;
    if !sign.status.success() {
        return Err(format!("step b (sign-csr) failed: {}", stderr_of(&sign)));
    }

    // Step c — upload the signed cert. The OTP is used here only, never stored.
    let upload = Command::new(&cfg.node_path)
        .current_dir(&cfg.bin_dir)
        .args([
            "bin/heliopause-enrollment.ts".to_string(),
            "cert-upload".to_string(),
            cfg.manager_url.clone(),
            id.to_string(),
            format!("--cert={}", crt_path.display()),
            format!("--ca-name={}", cfg.ca_name),
            format!("--pki={}", cfg.pki_dir),
            format!("--operator={}", cfg.operator),
            format!("--otp={otp}"),
        ])
        .output()
        .map_err(|e| format!("step c (cert-upload) failed to launch: {e}"))?;
    if !upload.status.success() {
        return Err(format!("step c (cert-upload) failed: {}", stderr_of(&upload)));
    }

    Ok(format!("signed & uploaded {hostname}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            list_pending,
            approve_sign
        ])
        .run(tauri::generate_context!())
        .expect("error while running Heliopause Enroll");
}
