// Heliopause Enroll — frontend. Uses the globally-injected Tauri API
// (app.withGlobalTauri = true) so no bundler is needed.
const invoke = window.__TAURI__.core.invoke;

const CONFIG_FIELDS = [
  "binDir",
  "managerUrl",
  "pkiDir",
  "operator",
  "caName",
  "nodePath",
];

// The current config, kept in memory and passed to every backend call.
let currentConfig = null;

const $ = (id) => document.getElementById(id);

async function ensureConfig() {
  if (!currentConfig) {
    currentConfig = await invoke("load_config");
  }
  return currentConfig;
}

// ---- CSR list -------------------------------------------------------------

function statusChip(status) {
  const chip = document.createElement("span");
  chip.className = "chip chip-" + String(status).toLowerCase();
  chip.textContent = status;
  return chip;
}

function renderCards(rows) {
  const container = $("cards");
  container.innerHTML = "";

  if (!rows || rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "no pending CSRs";
    container.appendChild(empty);
    return;
  }

  for (const row of rows) {
    const card = document.createElement("div");
    card.className = "card";

    const head = document.createElement("div");
    head.className = "card-head";
    const host = document.createElement("div");
    host.className = "hostname";
    host.textContent = row.hostname;
    head.appendChild(host);
    head.appendChild(statusChip(row.status));
    card.appendChild(head);

    const fpLabel = document.createElement("div");
    fpLabel.className = "fp-label";
    fpLabel.textContent = "csrSha256";
    card.appendChild(fpLabel);

    const fp = document.createElement("div");
    fp.className = "fingerprint";
    fp.textContent = row.csrSha256;
    card.appendChild(fp);

    const controls = document.createElement("div");
    controls.className = "card-controls";

    const otp = document.createElement("input");
    otp.type = "text";
    otp.className = "otp-input";
    otp.placeholder = "OTP";
    otp.autocomplete = "off";
    otp.spellcheck = false;
    controls.appendChild(otp);

    const btn = document.createElement("button");
    btn.className = "btn btn-primary";
    btn.textContent = "Approve & Sign";
    controls.appendChild(btn);
    card.appendChild(controls);

    const result = document.createElement("div");
    result.className = "card-result";
    card.appendChild(result);

    btn.addEventListener("click", async () => {
      result.textContent = "";
      result.className = "card-result";
      btn.disabled = true;
      otp.disabled = true;
      btn.textContent = "Working…";
      try {
        const cfg = await ensureConfig();
        const msg = await invoke("approve_sign", {
          cfg,
          id: row.id,
          hostname: row.hostname,
          expectSha256: row.csrSha256,
          otp: otp.value,
        });
        result.textContent = msg;
        result.className = "card-result ok";
        btn.textContent = "Done";
      } catch (err) {
        result.textContent = String(err);
        result.className = "card-result err";
        btn.disabled = false;
        otp.disabled = false;
        btn.textContent = "Approve & Sign";
      }
    });

    container.appendChild(card);
  }
}

async function refresh() {
  const btn = $("refresh-btn");
  const statusEl = $("list-status");
  btn.disabled = true;
  statusEl.className = "list-status";
  statusEl.textContent = "Loading…";
  try {
    const cfg = await ensureConfig();
    const rows = await invoke("list_pending", { cfg });
    renderCards(rows);
    statusEl.textContent = rows.length
      ? `${rows.length} pending`
      : "";
  } catch (err) {
    $("cards").innerHTML = "";
    statusEl.className = "list-status err";
    statusEl.textContent = String(err);
  } finally {
    btn.disabled = false;
  }
}

// ---- Settings modal -------------------------------------------------------

async function openSettings() {
  const cfg = await ensureConfig();
  for (const f of CONFIG_FIELDS) {
    $("cfg-" + f).value = cfg[f] ?? "";
  }
  $("settings-status").textContent = "";
  $("settings-status").className = "settings-status";
  $("settings-overlay").classList.remove("hidden");
}

function closeSettings() {
  $("settings-overlay").classList.add("hidden");
}

async function saveSettings() {
  const cfg = {};
  for (const f of CONFIG_FIELDS) {
    cfg[f] = $("cfg-" + f).value.trim();
  }
  const statusEl = $("settings-status");
  const saveBtn = $("settings-save");
  saveBtn.disabled = true;
  try {
    await invoke("save_config", { cfg });
    currentConfig = cfg;
    statusEl.className = "settings-status ok";
    statusEl.textContent = "Saved.";
    setTimeout(closeSettings, 500);
  } catch (err) {
    statusEl.className = "settings-status err";
    statusEl.textContent = String(err);
  } finally {
    saveBtn.disabled = false;
  }
}

// ---- Wire up --------------------------------------------------------------

window.addEventListener("DOMContentLoaded", () => {
  $("refresh-btn").addEventListener("click", refresh);
  $("settings-btn").addEventListener("click", openSettings);
  $("settings-cancel").addEventListener("click", closeSettings);
  $("settings-save").addEventListener("click", saveSettings);
  $("settings-overlay").addEventListener("click", (e) => {
    if (e.target === $("settings-overlay")) closeSettings();
  });

  // Preload config; leave the list empty until the operator hits Refresh
  // (so we never make a network call to the manager on startup).
  ensureConfig().catch((err) => {
    $("list-status").className = "list-status err";
    $("list-status").textContent = String(err);
  });
});
