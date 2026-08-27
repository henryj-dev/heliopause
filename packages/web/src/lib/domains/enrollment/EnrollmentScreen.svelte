<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { ageLabel } from "$lib/age";
  import { chromeFreshness } from "$lib/shell/freshness.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import type { WriteSpec } from "$lib/shell/write-ask";
  import { loginHref, shouldAskOtp } from "$lib/shell/who";
  import { whoQuery } from "$lib/shell/who.svelte";
  import CsrPane from "./CsrPane.svelte";
  import {
    appTokenState,
    appTokenTone,
    APP_TOKEN_STATE_KEY,
    auditActionLabel,
    auditDetailLine,
    daysUntil,
    enrollmentFocus,
    enrollmentPath,
    enrollmentPipeline,
    filteredRequests,
    readCsrFilter,
    requestCardClass,
    REQUEST_STATUS_KEY,
    requestTone,
    scopeLabel,
    shortDigest,
    TOKEN_STATE_KEY,
    tokenState,
    tokenTone,
  } from "./present";
  import {
    canDecideCsr,
    canIssueAppToken,
    canIssueToken,
    canRevokeAppToken,
    canRevokeCert,
    canRevokeToken,
    type AppTokenRow,
    type RequestRow,
    type TokenRow,
  } from "./store";
  import { ENROLLMENT_POLL_MS, enrollmentQuery } from "./query.svelte";
  import {
    appTokenCreateBody,
    certRevokeBody,
    certUploadBody,
    csrRejectBody,
    otpBody,
    tokenCreateBody,
    writeHeaders,
  } from "./write";

  const APP_SCOPES = ["enrollment:token-create", "enrollment:requests-read"];

  let { asked = "" }: { asked?: string } = $props();

  const enrollment = enrollmentQuery();
  const prefs = chromePrefs();
  const fresh = chromeFreshness();
  const who = whoQuery();
  const write = writeAsk();
  let hostname = $state("");
  let label = $state("");
  let note = $state("");
  let noteKind = $state<"ok" | "bad">("ok");
  let busy = $state("");
  let certFiles = $state<Record<string, File | undefined>>({});
  let caNames = $state<Record<string, string>>({});
  let revealed = $state<{ token: string; hostname: string } | null>(null);
  let tokenAck = $state(false);
  let appLabel = $state("");
  let appPattern = $state("");
  let appTtlDays = $state(90);
  let appScopes = $state<string[]>([...APP_SCOPES]);
  let revealedApp = $state<{ token: string; label: string } | null>(null);
  let appAck = $state(false);

  const filter = $derived(readCsrFilter(asked));
  const canWrite = $derived(who.state.kind === "ok" && who.state.view.canWrite);
  const stale = $derived(enrollment.state.kind === "ok" && enrollment.state.failCount > 0);
  const ageSec = $derived(
    enrollment.state.kind === "ok" ? Math.max(0, Math.floor((fresh.now - enrollment.state.lastOkAt) / 1000)) : 0,
  );
  const age = $derived(ageLabel(ageSec));

  $effect(() => {
    if (enrollment.state.kind !== "ok") {
      fresh.publish(null);
      return;
    }
    fresh.publish({
      lastOkAt: enrollment.state.lastOkAt,
      intervalMs: ENROLLMENT_POLL_MS,
      failCount: enrollment.state.failCount,
    });
    return () => fresh.publish(null);
  });

  onMount(() => {
    void enrollment.refresh();
    const id = setInterval(() => void enrollment.refresh(), ENROLLMENT_POLL_MS);
    return () => {
      clearInterval(id);
      write.cancel();
    };
  });

  function csrf(): string | null {
    return who.state.kind === "ok" ? who.state.view.csrf : null;
  }

  function askWrite(spec: Omit<WriteSpec, "needsOtp">) {
    const view = who.state.kind === "ok" ? who.state.view : null;
    return write.ask({ ...spec, needsOtp: shouldAskOtp(view) });
  }

  function fail(e: unknown): void {
    noteKind = "bad";
    note = e instanceof Error ? e.message : String(e);
  }

  async function post(path: string, body: string, okNote: string): Promise<string | null> {
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: writeHeaders(csrf()),
      body,
    });
    const answer = await res.json() as { error?: string; token?: string };
    if (!res.ok) throw new Error(answer.error ?? `HTTP ${res.status}`);
    noteKind = "ok";
    note = okNote;
    await enrollment.refresh();
    void who.refresh();
    return typeof answer.token === "string" && answer.token !== "" ? answer.token : null;
  }

  async function issueToken(): Promise<void> {
    const answer = await askWrite({ what: t(prefs.lang, "m.otpIssue") });
    if (answer === null) return;
    busy = "token-create";
    try {
      const token = await post("/api/enrollment/tokens", tokenCreateBody(hostname, label, answer.otp), t(prefs.lang, "m.tokenIssuedOnce"));
      if (token) {
        revealed = { token, hostname };
        tokenAck = false;
      }
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  async function copyRevealed(): Promise<void> {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.token);
    } catch (e) {
      fail(e);
    }
  }

  async function revokeToken(token: TokenRow): Promise<void> {
    const answer = await askWrite({
      what: t(prefs.lang, "m.otpRevokeToken"),
      warning: t(prefs.lang, "m.revokeTokenConfirm", { id: token.id }),
    });
    if (answer === null) return;
    busy = `token-revoke:${token.id}`;
    try {
      await post(`/api/enrollment/tokens/${encodeURIComponent(token.id)}/revoke`, otpBody(answer.otp), t(prefs.lang, "m.tokenRevoked"));
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  async function issueAppToken(): Promise<void> {
    if (appLabel.trim() === "") {
      fail(new Error(t(prefs.lang, "m.appNeedLabel")));
      return;
    }
    if (appScopes.length === 0) {
      fail(new Error(t(prefs.lang, "m.appNeedScope")));
      return;
    }
    if (appPattern.trim() === "") {
      fail(new Error(t(prefs.lang, "m.appNeedPattern")));
      return;
    }
    if (!Number.isInteger(appTtlDays) || appTtlDays < 1) {
      fail(new Error(t(prefs.lang, "m.appNeedTtl")));
      return;
    }
    const answer = await askWrite({ what: t(prefs.lang, "m.otpIssueApp") });
    if (answer === null) return;
    busy = "app-token-create";
    try {
      const token = await post(
        "/api/enrollment/app-tokens",
        appTokenCreateBody(appLabel, appScopes, appPattern, appTtlDays * 86400, answer.otp),
        t(prefs.lang, "m.appTokenIssuedOnce"),
      );
      if (token) {
        revealedApp = { token, label: appLabel };
        appAck = false;
      }
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  async function copyRevealedApp(): Promise<void> {
    if (!revealedApp) return;
    try {
      await navigator.clipboard.writeText(revealedApp.token);
    } catch (e) {
      fail(e);
    }
  }

  async function revokeAppToken(row: AppTokenRow): Promise<void> {
    const answer = await askWrite({
      what: t(prefs.lang, "m.otpRevokeApp"),
      warning: t(prefs.lang, "m.revokeAppConfirm", { id: row.id }),
    });
    if (answer === null) return;
    busy = `app-token-revoke:${row.id}`;
    try {
      await post(
        `/api/enrollment/app-tokens/${encodeURIComponent(row.id)}/revoke`,
        otpBody(answer.otp),
        t(prefs.lang, "m.appTokenRevoked"),
      );
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  function downloadCsr(request: RequestRow): void {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([request.csrPem], { type: "application/pkcs10" }));
    link.download = `${request.hostname}-${request.csrSha256.slice(0, 12)}.csr.pem`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function rejectCsr(request: RequestRow): Promise<void> {
    const answer = await askWrite({
      what: t(prefs.lang, "m.otpReject"),
      reason: true,
      reasonLabel: t(prefs.lang, "m.rejectReason"),
    });
    if (answer === null) return;
    busy = `csr-reject:${request.id}`;
    try {
      await post(
        `/api/enrollment/requests/${encodeURIComponent(request.id)}/reject`,
        csrRejectBody(answer.reason, answer.otp),
        t(prefs.lang, "m.csrRejected"),
      );
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  async function uploadCert(request: RequestRow): Promise<void> {
    const file = certFiles[request.id];
    const caName = (caNames[request.id] ?? "").trim();
    if (!file || !caName) {
      fail(new Error(t(prefs.lang, "m.chooseCert")));
      return;
    }
    const answer = await askWrite({ what: t(prefs.lang, "m.otpUpload") });
    if (answer === null) return;
    busy = `cert-upload:${request.id}`;
    try {
      await post(
        `/api/enrollment/requests/${encodeURIComponent(request.id)}/certificate`,
        certUploadBody(await file.text(), caName, answer.otp),
        t(prefs.lang, "m.certUploaded"),
      );
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  async function revokeCert(request: RequestRow): Promise<void> {
    if (!request.certificatePem) return;
    const answer = await askWrite({
      what: t(prefs.lang, "m.otpRevokeCert"),
      reason: true,
      reasonLabel: t(prefs.lang, "m.revokeReason"),
    });
    if (answer === null) return;
    busy = `cert-revoke:${request.id}`;
    try {
      await post("/api/enrollment/revocations", certRevokeBody(request.certificatePem, answer.reason, answer.otp), t(prefs.lang, "m.certRevoked"));
    } catch (e) {
      fail(e);
    } finally {
      busy = "";
    }
  }

  function setCertFile(id: string, files: FileList | null): void {
    certFiles = { ...certFiles, [id]: files?.[0] };
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.enrollment")}</title>
</svelte:head>

{#if enrollment.state.kind === "loading"}
  <div class="empty-card">
    <p>{t(prefs.lang, "m.readingEnrollment")}</p>
  </div>
{:else if enrollment.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInEnrollment")}</p>
  <p><a href={loginHref(`${base}${enrollmentPath(filter)}`)}>{t(prefs.lang, "m.signIn")}</a></p>
{:else if enrollment.state.kind === "absent"}
  <div class="empty-card">
    <div class="lead">{t(prefs.lang, "m.enrollmentAbsent")}</div>
  </div>
{:else if enrollment.state.kind === "error"}
  <div class="banner bad">
    <div class="lead">{t(prefs.lang, "m.enrollmentError", { message: enrollment.state.message })}</div>
    <p class="act">
      <button type="button" onclick={() => void enrollment.refresh()}>{t(prefs.lang, "m.reread")}</button>
    </p>
  </div>
{:else}
  {@const view = enrollment.state.view}
  {@const pipe = enrollmentPipeline(view, fresh.now)}
  {@const focus = enrollmentFocus(pipe)}
  {@const shown = filteredRequests(view.requests, filter)}
  {#if stale}
    <div class="banner warn hatch">
      <div class="lead">{t(prefs.lang, "m.staleBanner", { age })}</div>
      <div>
        {t(prefs.lang, "m.staleFails", { n: enrollment.state.failCount, error: enrollment.state.lastFail ?? "" })}
      </div>
      <p>{t(prefs.lang, "m.staleNoIssue")}</p>
      <p class="act">
        <button type="button" onclick={() => void enrollment.refresh()}>{t(prefs.lang, "m.reread")}</button>
      </p>
    </div>
  {/if}

  <ol class="pipe" aria-label={t(prefs.lang, "m.pipeLine")}>
    <li class="pipe-step" class:now={focus === "tokens"} class:on={filter === null}>
      <a href="{base}{enrollmentPath(null)}" class="vpc-card">
        <div class="hd"><span class="n">1</span> {t(prefs.lang, "m.pipeTokens")}</div>
        <div class="clock">{pipe.tokens}</div>
        <div class="meta">{t(prefs.lang, "m.pipeUnused", { n: pipe.unused })}</div>
      </a>
    </li>
    <li class="pipe-join" aria-hidden="true"></li>
    <li class="pipe-step" class:now={focus === "pending"} class:on={filter === "pending"}>
      <a href="{base}{enrollmentPath("pending")}" class="vpc-card {pipe.pending > 0 ? 'warn' : ''}">
        <div class="hd"><span class="n">2</span> {t(prefs.lang, "m.pipePending")}</div>
        <div class="clock">{pipe.pending}</div>
        <div class="meta">{t(prefs.lang, "m.pipePendingNote")}</div>
      </a>
    </li>
    <li class="pipe-join" aria-hidden="true"></li>
    <li class="pipe-step" class:now={focus === "signed"} class:on={filter === "signed"}>
      <a href="{base}{enrollmentPath("signed")}" class="vpc-card {pipe.signedWait > 0 ? 'warn' : ''}">
        <div class="hd"><span class="n">3</span> {t(prefs.lang, "m.pipeSigned")}</div>
        <div class="clock">{pipe.signedWait}</div>
        <div class="meta">{t(prefs.lang, "m.pipeSignedNote")}</div>
      </a>
    </li>
  </ol>
  <div class="pipe-aside" aria-label={t(prefs.lang, "m.pipeAside")}>
    <a href="{base}{enrollmentPath("conflict")}" class="vpc-card {pipe.conflict > 0 ? 'bad' : ''}" class:on={filter === "conflict"}>
      <div class="hd">{t(prefs.lang, "m.pipeConflict")}</div>
      <div class="clock">{pipe.conflict}</div>
      <div class="meta">{t(prefs.lang, "m.pipeConflictNote")}</div>
    </a>
    <a href="#revoked" class="vpc-card">
      <div class="hd">{t(prefs.lang, "m.pipeRevoked")}</div>
      <div class="clock">{pipe.revocations}</div>
      <div class="meta">{t(prefs.lang, "m.pipeRevokedNote")}</div>
    </a>
  </div>

  {#if revealed}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.tokenOnce")}</div>
      <p>{t(prefs.lang, "m.tokenOnceNote")}</p>
      <p><code class="name">{revealed.token}</code> · {revealed.hostname}</p>
      <p class="act">
        <button type="button" onclick={() => void copyRevealed()}>{t(prefs.lang, "m.copy")}</button>
        <label>
          <input type="checkbox" bind:checked={tokenAck}>
          {t(prefs.lang, "m.tokenAck")}
        </label>
        <button type="button" disabled={!tokenAck} onclick={() => (revealed = null, tokenAck = false)}>
          {t(prefs.lang, "m.tokenDismiss")}
        </button>
      </p>
      {#if !tokenAck}
        <p class="dim">{t(prefs.lang, "m.tokenNeedAck")}</p>
      {/if}
    </div>
  {/if}

  {#if canIssueToken(canWrite, stale)}
    <p>
      <input bind:value={hostname} placeholder={t(prefs.lang, "m.hostname")}>
      <input bind:value={label} placeholder={t(prefs.lang, "m.label")}>
      <button type="button" disabled={busy !== ""} onclick={() => void issueToken()}>{t(prefs.lang, "m.issueToken")}</button>
    </p>
  {/if}

  <h2>{t(prefs.lang, "m.nodeTokens")}</h2>
  {#if view.tokens.length === 0}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyTokens")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyTokensExplain")}</p>
    </div>
  {:else}
    <div class="scroll" class:stale-hold={stale}>
    <table>
      <thead>
        <tr>
          <th>{t(prefs.lang, "c.id")}</th>
          <th>{t(prefs.lang, "c.hostname")}</th>
          <th>{t(prefs.lang, "c.created")}</th>
          <th>{t(prefs.lang, "c.expires")}</th>
          <th>{t(prefs.lang, "c.lastUsed")}</th>
          <th>{t(prefs.lang, "c.state")}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each view.tokens as token (token.id)}
          {@const state = tokenState(token, fresh.now)}
          <tr>
            <td><code>{token.id}</code></td>
            <td>{token.hostname}</td>
            <td>{token.createdAt}</td>
            <td>{token.expiresAt ?? t(prefs.lang, "m.never")}</td>
            <td>{token.lastUsedAt ?? t(prefs.lang, "m.never")}</td>
            <td>
              <span class="chip {tokenTone(state)}">{t(prefs.lang, TOKEN_STATE_KEY[state])}</span>
            </td>
            <td>
              {#if canRevokeToken(token, canWrite)}
                <button type="button" disabled={busy !== ""} onclick={() => void revokeToken(token)}>{t(prefs.lang, "m.revoke")}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}

  <h2>{t(prefs.lang, "m.appTokens")}</h2>
  <p class="dim">{t(prefs.lang, "m.appTokensExplain")}</p>

  {#if revealedApp}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.tokenOnce")}</div>
      <p>{t(prefs.lang, "m.tokenOnceNote")}</p>
      <p><code class="name">{revealedApp.token}</code> · {revealedApp.label}</p>
      <p class="act">
        <button type="button" onclick={() => void copyRevealedApp()}>{t(prefs.lang, "m.copy")}</button>
        <label>
          <input type="checkbox" bind:checked={appAck}>
          {t(prefs.lang, "m.tokenAck")}
        </label>
        <button type="button" disabled={!appAck} onclick={() => (revealedApp = null, appAck = false)}>
          {t(prefs.lang, "m.tokenDismiss")}
        </button>
      </p>
      {#if !appAck}
        <p class="dim">{t(prefs.lang, "m.tokenNeedAck")}</p>
      {/if}
    </div>
  {/if}

  {#if canIssueAppToken(canWrite, stale)}
    <p>
      <input bind:value={appLabel} placeholder={t(prefs.lang, "m.appLabel")}>
      <span class="dim">{t(prefs.lang, "m.appScopesLabel")}</span>
      {#each APP_SCOPES as scope (scope)}
        <label>
          <input type="checkbox" bind:group={appScopes} value={scope}>
          {scopeLabel(scope, prefs.lang)}
        </label>
      {/each}
      <input bind:value={appPattern} placeholder={t(prefs.lang, "m.appPattern")}>
      <input type="number" min="1" bind:value={appTtlDays} aria-label={t(prefs.lang, "m.appTtlDays")}>
      <button type="button" disabled={busy !== ""} onclick={() => void issueAppToken()}>{t(prefs.lang, "m.issueAppToken")}</button>
    </p>
  {/if}

  {#if view.appTokens.length === 0}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyAppTokens")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyAppTokensExplain")}</p>
    </div>
  {:else}
    <div class="scroll" class:stale-hold={stale}>
    <table>
      <thead>
        <tr>
          <th>{t(prefs.lang, "c.id")}</th>
          <th>{t(prefs.lang, "c.label")}</th>
          <th>{t(prefs.lang, "m.scopes")}</th>
          <th>{t(prefs.lang, "m.hostnamePattern")}</th>
          <th>{t(prefs.lang, "c.created")}</th>
          <th>{t(prefs.lang, "c.expires")}</th>
          <th>{t(prefs.lang, "c.lastUsed")}</th>
          <th>{t(prefs.lang, "c.state")}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each view.appTokens as row (row.id)}
          {@const state = appTokenState(row, fresh.now)}
          {@const left = daysUntil(row.expiresAt, fresh.now)}
          <tr>
            <td><code>{row.id}</code></td>
            <td>{row.label}</td>
            <td>{row.scopes.map((s) => scopeLabel(s, prefs.lang)).join(", ")}</td>
            <td><code>{row.hostnamePattern}</code></td>
            <td>{row.createdAt}</td>
            <td>{row.expiresAt}</td>
            <td>{row.lastUsedAt ?? t(prefs.lang, "m.never")}</td>
            <td>
              <span class="chip {appTokenTone(state)}">{t(prefs.lang, APP_TOKEN_STATE_KEY[state])}</span>
              {#if state === "expiring" && left !== null}
                <span class="dim">{t(prefs.lang, "m.expiringDays", { n: left })}</span>
              {/if}
            </td>
            <td>
              {#if canRevokeAppToken(row, canWrite)}
                <button type="button" disabled={busy !== ""} onclick={() => void revokeAppToken(row)}>{t(prefs.lang, "m.revoke")}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}

  <h2>{t(prefs.lang, "m.certRequests")}</h2>
  {#if filter}
    <p class="dim">
      {t(prefs.lang, REQUEST_STATUS_KEY[filter])}
      · <a href="{base}{enrollmentPath(null)}">{t(prefs.lang, "m.filterAll")}</a>
    </p>
  {/if}
  {#if view.requests.length === 0}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyRequests")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyRequestsExplain")}</p>
    </div>
  {:else if shown.length === 0}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyFilter", { status: filter ? t(prefs.lang, REQUEST_STATUS_KEY[filter]) : "" })}</div>
      <p class="dim">{t(prefs.lang, "m.emptyFilterExplain")}</p>
    </div>
  {:else}
    <div class:stale-hold={stale} style="display:flex;flex-direction:column;gap:16px">
    {#each shown as request (request.id)}
      <article class="plan-card {requestCardClass(request)}">
        <p>
          <span class="chip {requestTone(request.status)}">{t(prefs.lang, REQUEST_STATUS_KEY[request.status])}</span>
          <span class="name">{request.hostname}</span>
          <code>{request.id}</code>
        </p>
        <p class="dim">
          {t(prefs.lang, "m.requestMeta", {
            pub: shortDigest(request.publicKeySha256),
            token: request.nodeTokenId,
            source: request.sourceIp ?? t(prefs.lang, "m.notReported"),
            at: request.createdAt,
          })}
        </p>
        <CsrPane {request} />
        {#if request.status === "conflict"}
          <p>{t(prefs.lang, "m.conflictExplain")}</p>
        {/if}
        {#if request.status === "signed" && !request.retrievedAt}
          <p>{t(prefs.lang, "m.signedWaitExplain")}</p>
        {/if}
        {#if request.decisionReason}
          <p>{request.decisionReason}</p>
        {/if}
        {#if canDecideCsr(request, canWrite)}
          <p>
            <button type="button" onclick={() => downloadCsr(request)}>{t(prefs.lang, "m.downloadCsr")}</button>
            <button type="button" disabled={busy !== ""} onclick={() => void rejectCsr(request)}>{t(prefs.lang, "m.reject")}</button>
            <input type="file" accept=".pem,.crt" onchange={(ev) => setCertFile(request.id, ev.currentTarget.files)}>
            <input placeholder={t(prefs.lang, "m.caName")} bind:value={caNames[request.id]}>
            <button type="button" disabled={busy !== ""} onclick={() => void uploadCert(request)}>
              {t(prefs.lang, "m.uploadCert")}
            </button>
          </p>
        {:else if canRevokeCert(request, canWrite)}
          <p>
            <button type="button" disabled={busy !== ""} onclick={() => void revokeCert(request)}>
              {t(prefs.lang, "m.revokeCert")}
            </button>
          </p>
        {/if}
      </article>
    {/each}
    </div>
  {/if}

  <h2 id="revoked">{t(prefs.lang, "m.revokedCerts")}</h2>
  {#if view.revocations.length === 0}
    <p>{t(prefs.lang, "m.none")}</p>
  {:else}
    <ul>
      {#each view.revocations as row (row.fingerprint256 + row.revokedAt)}
        <li>
          <code>sha256:{row.fingerprint256}</code>
          · {row.subject ?? ""} · {row.reason} · {row.revokedAt}
        </li>
      {/each}
    </ul>
  {/if}

  <h2>{t(prefs.lang, "m.trail")}</h2>
  {#if view.events === null}
    <p>{t(prefs.lang, "m.trailUnread")}</p>
  {:else if view.events.length === 0}
    <p>{t(prefs.lang, "m.trailNone")}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{t(prefs.lang, "c.when")}</th>
          <th>{t(prefs.lang, "c.actor")}</th>
          <th>{t(prefs.lang, "c.action")}</th>
          <th>{t(prefs.lang, "c.target")}</th>
          <th>{t(prefs.lang, "c.from")}</th>
          <th>{t(prefs.lang, "c.detail")}</th>
        </tr>
      </thead>
      <tbody>
        {#each view.events.slice().reverse() as event (event.at + event.action + event.target)}
          <tr>
            <td>{event.at}</td>
            <td>{event.actor}</td>
            <td title={event.action}>{auditActionLabel(event.action, prefs.lang)}</td>
            <td><code>{event.target}</code></td>
            <td>{event.sourceIp ?? t(prefs.lang, "m.notReported")}</td>
            <td>{auditDetailLine(event.detail, prefs.lang)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}

{#if note}
  <p>{noteKind === "bad" ? t(prefs.lang, "m.errorPrefix") : ""}{note}</p>
{/if}

{#if write.pending}
  <WriteDialog spec={write.pending.spec} onsubmit={write.submit} oncancel={write.cancel} />
{/if}

<style>
  .stale-hold { opacity: 0.72; }
</style>
