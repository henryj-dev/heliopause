<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { page } from "$app/state";
  import { replaceState } from "$app/navigation";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { loginHref } from "$lib/shell/who";
  import { whoQuery } from "$lib/shell/who.svelte";
  import { writeHeaders } from "./write";
  import { errorText } from "./answer";
  import { linkResult, ME_PATH, ME_SESSIONS_PATH, readMe, readSessions, sessionPath, type MeView, type SessionRow } from "./account";
  import ChangePassword from "./ChangePassword.svelte";
  import SsoAccounts from "./SsoAccounts.svelte";

  type MeState =
    | { kind: "loading" }
    | { kind: "unauth" }
    | { kind: "notMember" }
    | { kind: "error"; message: string }
    | { kind: "ok"; me: MeView };

  const prefs = chromePrefs();
  const who = whoQuery();
  let view = $state<MeState>({ kind: "loading" });
  let sessions = $state<SessionRow[]>([]);
  let note = $state("");
  let noteBad = $state(false);
  let busy = $state(false);

  const csrf = $derived(view.kind === "ok" ? view.me.csrf : null);

  async function load(): Promise<void> {
    try {
      const res = await fetch(ME_PATH, { credentials: "same-origin" });
      const body: unknown = await res.json().catch(() => null);
      if (res.status === 401) view = { kind: "unauth" };
      else if (res.status === 403) view = { kind: "notMember" };
      else if (!res.ok) view = { kind: "error", message: errorText(body) || `HTTP ${res.status}` };
      else {
        const me = readMe(body);
        view = me ? { kind: "ok", me } : { kind: "error", message: "unreadable answer" };
      }
    } catch (e) {
      view = { kind: "error", message: e instanceof Error ? e.message : String(e) };
    }
    if (view.kind === "ok" && !view.me.mustChange) await loadSessions();
  }

  async function loadSessions(): Promise<void> {
    try {
      const res = await fetch(ME_SESSIONS_PATH, { credentials: "same-origin" });
      sessions = res.ok ? readSessions(await res.json()) : [];
    } catch {
      sessions = [];
    }
  }

  onMount(() => {
    // The SSO callback lands here with `?link=`; say what happened once, and drop it from the address.
    const linked = linkResult(page.url.searchParams.get("link"));
    if (linked) {
      done(t(prefs.lang, linked.key), !linked.ok);
      replaceState(`${base}/account`, {});
    }
    void load();
  });

  function done(text: string, bad = false): void {
    note = text;
    noteBad = bad;
  }

  async function changed(ended: number): Promise<void> {
    const wasMustChange = view.kind === "ok" && view.me.mustChange;
    done(t(prefs.lang, "m.acChanged", { n: ended }));
    if (wasMustChange) {
      // The rest of the console answers now; a full load lets the chrome read it again.
      location.assign(`${base}/fleet`);
      return;
    }
    await load();
  }

  async function end(path: string, current: boolean): Promise<void> {
    busy = true;
    try {
      const res = await fetch(path, { method: "DELETE", credentials: "same-origin", headers: writeHeaders(csrf) });
      const body: unknown = await res.json().catch(() => null);
      if (!res.ok) return done(errorText(body) || `HTTP ${res.status}`, true);
      if (current) {
        location.assign(`${base}/login`);
        return;
      }
      const n = typeof (body as { ended?: unknown })?.ended === "number" ? (body as { ended: number }).ended : 0;
      done(t(prefs.lang, "m.acEnded", { n }));
      await loadSessions();
    } catch (e) {
      done(e instanceof Error ? e.message : String(e), true);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.account")}</title>
</svelte:head>

{#if view.kind === "loading"}
  <p class="dim">{t(prefs.lang, "m.acReading")}</p>
{:else if view.kind === "unauth"}
  <p>{t(prefs.lang, "m.acSignIn")}</p>
  <p><a href={loginHref(`${base}/account`)}>{t(prefs.lang, "m.signIn")}</a></p>
{:else if view.kind === "notMember"}
  <p>{t(prefs.lang, "m.acNotMember")}</p>
{:else if view.kind === "error"}
  <div class="banner bad">
    <div class="lead">{t(prefs.lang, "m.acError", { message: view.message })}</div>
  </div>
{:else if view.me.mustChange}
  <div class="banner warn">
    <div class="lead">{t(prefs.lang, "m.acMustChange")}</div>
  </div>
  <ChangePassword {csrf} onchanged={(n) => void changed(n)} />
  <p class="act">
    <button type="button" onclick={() => void who.signOut(csrf)}>{t(prefs.lang, "m.signOut")}</button>
  </p>
{:else}
  {@const me = view.me}
  <dl class="facts">
    <dt>{t(prefs.lang, "m.acUsername")}</dt><dd><code>{me.username}</code></dd>
    <dt>{t(prefs.lang, "m.acPrincipal")}</dt><dd><code>{me.principalName}</code></dd>
    <dt>{t(prefs.lang, "m.acEmail")}</dt><dd>{me.email ?? t(prefs.lang, "m.none")}</dd>
    <dt>{t(prefs.lang, "m.acRoles")}</dt><dd>{me.roles.join(", ")}</dd>
    <dt>{t(prefs.lang, "m.acOtp")}</dt>
    <dd>{me.otpConfirmedAt ? t(prefs.lang, "m.acOtpConfirmed", { at: me.otpConfirmedAt }) : t(prefs.lang, "m.acOtpNone")}</dd>
  </dl>

  {#if me.hasPassword}
    <ChangePassword {csrf} onchanged={(n) => void changed(n)} />
  {:else}
    <p class="dim">{t(prefs.lang, "m.acPasswordNone")}</p>
  {/if}

  <SsoAccounts {me} onchanged={(key) => { done(t(prefs.lang, key)); void load(); }} />

  <h2>{t(prefs.lang, "m.acSessions")}</h2>
  <p class="dim">{t(prefs.lang, "m.acSessionsNote")}</p>
  <table>
    <thead>
      <tr>
        <th>{t(prefs.lang, "m.acSignedInAt")}</th>
        <th>{t(prefs.lang, "m.acLastSeen")}</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each sessions as s (s.id)}
        <tr>
          <td>{s.createdAt}</td>
          <td>{s.lastSeenAt}</td>
          <td>
            {#if s.current}<span class="chip">{t(prefs.lang, "m.acThisBrowser")}</span>{/if}
            <button type="button" disabled={busy} onclick={() => void end(sessionPath(s.id), s.current)}>{t(prefs.lang, "m.acEnd")}</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if sessions.some((s) => !s.current)}
    <p class="act">
      <button type="button" disabled={busy} onclick={() => void end(ME_SESSIONS_PATH, false)}>{t(prefs.lang, "m.acEndOthers")}</button>
    </p>
  {/if}
{/if}

{#if note}
  <p>{noteBad ? t(prefs.lang, "m.errorPrefix") : ""}{note}</p>
{/if}

<style>
  .facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0 0 16px; }
  .facts dt { color: var(--text-3); }
  .facts dd { margin: 0; }
</style>
