<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { readInviteAccept, repeatProblem, type Refusal } from "./answer";
  import PasswordHint from "./PasswordHint.svelte";
  import RefusalNote from "./RefusalNote.svelte";
  import { clearFragment, readFragmentToken, INVITE_ACCEPT_PATH, inviteAcceptBody } from "./token";

  const prefs = chromePrefs();
  // Read once from the fragment on mount; after that the page holds it only in memory.
  let token = $state<string | null>(null);
  let read = $state(false);
  let username = $state("");
  let password = $state("");
  let repeat = $state("");
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);
  let created = $state<string | null>(null);

  onMount(() => {
    token = readFragmentToken(location.hash);
    read = true;
    clearFragment();
  });

  async function submit(): Promise<void> {
    if (!token) return;
    const problem = repeatProblem(password, repeat);
    if (problem) {
      refusal = { key: problem, detail: "", problems: [] };
      return;
    }
    busy = true;
    refusal = null;
    try {
      const res = await fetch(INVITE_ACCEPT_PATH, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: inviteAcceptBody(token, username, password),
      });
      const body: unknown = await res.json().catch(() => null);
      refusal = readInviteAccept(res.status, body);
      if (!refusal) {
        const name = (body as { username?: unknown } | null)?.username;
        created = typeof name === "string" ? name : username.trim();
        password = repeat = "";
      }
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.invite")}</title>
  <meta name="referrer" content="no-referrer">
</svelte:head>

<h2>{t(prefs.lang, "m.ivHeading")}</h2>

{#if created}
  <div class="banner ok">
    <div class="lead">{t(prefs.lang, "m.ivDone", { username: created })}</div>
  </div>
  <p><a href="{base}/login">{t(prefs.lang, "m.goLogin")}</a></p>
{:else if !read}
  <p class="dim">…</p>
{:else if !token}
  <p>{t(prefs.lang, "m.ivNoToken")}</p>
{:else}
  <p class="dim">{t(prefs.lang, "m.ivLede")}</p>
  {#if refusal}
    <RefusalNote {refusal} />
  {/if}
  <form
    class="stack"
    onsubmit={(e) => {
      e.preventDefault();
      void submit();
    }}
  >
    <label>
      {t(prefs.lang, "m.loginUsername")}
      <input autocomplete="username" spellcheck="false" bind:value={username} required>
    </label>
    <label>
      {t(prefs.lang, "m.loginPassword")}
      <input type="password" autocomplete="new-password" bind:value={password} required>
    </label>
    <label>
      {t(prefs.lang, "m.ivRepeat")}
      <input type="password" autocomplete="new-password" bind:value={repeat} required>
    </label>
    <PasswordHint />
    <p class="act">
      <button type="submit" disabled={busy}>{t(prefs.lang, "m.ivSubmit")}</button>
    </p>
  </form>
{/if}

<style>
  .stack { display: grid; gap: 12px; }
  .stack label { display: grid; gap: 4px; }
</style>
