<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { page } from "$app/state";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import type { Refusal } from "./answer";
  import RefusalNote from "./RefusalNote.svelte";
  import {
    afterSignIn,
    loginBody,
    METHODS_PATH,
    nextStep,
    PASSWORD_LOGIN_PATH,
    readLogin,
    readMethods,
    ssoHref,
    type LoginStep,
    type Methods,
  } from "./login";

  const prefs = chromePrefs();
  const next = $derived(page.url.searchParams.get("next"));

  let methods = $state<Methods | null>(null);
  let methodsFailed = $state(false);
  let step = $state<LoginStep>("password");
  let username = $state("");
  let password = $state("");
  let code = $state("");
  let wrongCode = $state(false);
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);

  onMount(async () => {
    try {
      const res = await fetch(METHODS_PATH, { credentials: "same-origin" });
      methods = res.ok ? readMethods(await res.json()) : { password: false, sso: false };
      methodsFailed = !res.ok;
    } catch {
      methods = { password: false, sso: false };
      methodsFailed = true;
    }
    // SSO is the only way in: this page has nothing to ask, so go on to the IdP.
    if (methods.sso && !methods.password) location.replace(ssoHref(next, base));
  });

  async function submit(): Promise<void> {
    if (busy) return;
    busy = true;
    refusal = null;
    const otp = step === "otp" ? code.trim() : null;
    try {
      const res = await fetch(PASSWORD_LOGIN_PATH, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: loginBody(username, password, otp),
      });
      const answer = readLogin(res.status, await res.json().catch(() => null), otp !== null);
      step = nextStep(step, answer);
      if (answer.kind === "signedIn") {
        // A full load, so the chrome starts again with the new session's identity.
        location.assign(afterSignIn(answer.mustChange, next, base));
        return;
      }
      if (answer.kind === "needOtp") {
        wrongCode = answer.wrongCode;
        code = "";
      } else {
        refusal = answer.refusal;
      }
      if (step === "password") password = "";
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    } finally {
      busy = false;
    }
  }

  function restart(): void {
    step = "password";
    password = "";
    code = "";
    wrongCode = false;
    refusal = null;
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.login")}</title>
</svelte:head>

<h2>{t(prefs.lang, "m.loginHeading")}</h2>

{#if methods === null}
  <p class="dim">{t(prefs.lang, "m.loginReading")}</p>
{:else if methods.sso && !methods.password}
  <p class="dim">{t(prefs.lang, "m.loginToSso")}</p>
  <p><a href={ssoHref(next, base)}>{t(prefs.lang, "m.loginSso")}</a></p>
{:else if !methods.password}
  <p>{t(prefs.lang, methodsFailed ? "m.loginMethodsError" : "m.loginNone")}</p>
{:else}
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
      <input name="username" autocomplete="username" spellcheck="false" bind:value={username} readonly={step === "otp"} required>
    </label>
    <label>
      {t(prefs.lang, "m.loginPassword")}
      <input name="password" type="password" autocomplete="current-password" bind:value={password} readonly={step === "otp"} required>
    </label>
    {#if step === "otp"}
      <p class="dim">{t(prefs.lang, wrongCode ? "m.loginWrongCode" : "m.loginOtpNote")}</p>
      <label>
        {t(prefs.lang, "m.otpCode")}
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="otp"
          name="otp"
          inputmode="numeric"
          autocomplete="one-time-code"
          spellcheck="false"
          bind:value={code}
          required
          autofocus
        >
      </label>
    {/if}
    <p class="act">
      <button type="submit" disabled={busy}>{t(prefs.lang, "m.loginSubmit")}</button>
      {#if step === "otp"}
        <button type="button" onclick={restart}>{t(prefs.lang, "m.loginBack")}</button>
      {/if}
    </p>
  </form>
  {#if methods.sso}
    <p class="dim">{t(prefs.lang, "m.loginOr")}</p>
    <p><a href={ssoHref(next, base)}>{t(prefs.lang, "m.loginSso")}</a></p>
  {/if}
{/if}

<style>
  .stack { display: grid; gap: 12px; }
  .stack label { display: grid; gap: 4px; }
  .otp { font-family: var(--font-mono); letter-spacing: 0.2em; }
</style>
