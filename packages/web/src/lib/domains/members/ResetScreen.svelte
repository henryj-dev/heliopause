<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { readReset, repeatProblem, type Refusal } from "./answer";
  import PasswordHint from "./PasswordHint.svelte";
  import RefusalNote from "./RefusalNote.svelte";
  import { clearFragment, readFragmentToken, RESET_PATH, resetBody } from "./token";

  const prefs = chromePrefs();
  // Read once from the fragment on mount; after that the page holds it only in memory.
  let token = $state<string | null>(null);
  let read = $state(false);
  let password = $state("");
  let repeat = $state("");
  let code = $state("");
  let needOtp = $state(false);
  let wrongCode = $state(false);
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);
  let done = $state(false);

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
    const otp = needOtp ? code.trim() : null;
    try {
      const res = await fetch(RESET_PATH, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: resetBody(token, password, otp),
      });
      const answer = readReset(res.status, await res.json().catch(() => null), otp !== null);
      if (answer.kind === "done") {
        done = true;
        password = repeat = code = "";
      } else if (answer.kind === "needOtp") {
        needOtp = true;
        wrongCode = answer.wrongCode;
        code = "";
      } else {
        refusal = answer.refusal;
      }
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.reset")}</title>
  <meta name="referrer" content="no-referrer">
</svelte:head>

<h2>{t(prefs.lang, "m.rsHeading")}</h2>

{#if done}
  <div class="banner ok">
    <div class="lead">{t(prefs.lang, "m.rsDone")}</div>
  </div>
  <p><a href="{base}/login">{t(prefs.lang, "m.goLogin")}</a></p>
{:else if !read}
  <p class="dim">…</p>
{:else if !token}
  <p>{t(prefs.lang, "m.rsNoToken")}</p>
{:else}
  <p class="dim">{t(prefs.lang, "m.rsLede")}</p>
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
      {t(prefs.lang, "m.acNext")}
      <input type="password" autocomplete="new-password" bind:value={password} required>
    </label>
    <label>
      {t(prefs.lang, "m.acRepeat")}
      <input type="password" autocomplete="new-password" bind:value={repeat} required>
    </label>
    <PasswordHint />
    {#if needOtp}
      <p class="dim">{t(prefs.lang, wrongCode ? "m.loginWrongCode" : "m.rsOtpNote")}</p>
      <label>
        {t(prefs.lang, "m.otpCode")}
        <input class="otp" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" bind:value={code} required>
      </label>
    {/if}
    <p class="act">
      <button type="submit" disabled={busy}>{t(prefs.lang, "m.rsSubmit")}</button>
    </p>
  </form>
{/if}

<style>
  .stack { display: grid; gap: 12px; }
  .stack label { display: grid; gap: 4px; }
  .otp { font-family: var(--font-mono); letter-spacing: 0.2em; }
</style>
