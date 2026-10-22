<script lang="ts">
  // The account page's linked SSO accounts: the list, "link an SSO account", and unlink. Both writes
  // ask for the current password first (and a writer's or admin's code), in this form.
  import { onMount } from "svelte";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { writeHeaders } from "./write";
  import type { Refusal } from "./answer";
  import RefusalNote from "./RefusalNote.svelte";
  import { METHODS_PATH, readMethods } from "./login";
  import {
    identityPath, LINK_START_PATH, readLinkStart, readReauth, reauthBody, reauthNeedsOtp, type MeView,
  } from "./account";

  let { me, onchanged }: { me: MeView; onchanged: (key: "m.acUnlinked") => void } = $props();

  const prefs = chromePrefs();
  const needsOtp = $derived(reauthNeedsOtp(me.roles));
  let sso = $state(false);
  // What the password form is confirming, or null when it is closed.
  let confirming = $state<{ kind: "link" } | { kind: "unlink"; id: string } | null>(null);
  let password = $state("");
  let code = $state("");
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);

  onMount(async () => {
    try {
      const res = await fetch(METHODS_PATH, { credentials: "same-origin" });
      sso = res.ok && readMethods(await res.json()).sso;
    } catch {
      sso = false;
    }
  });

  function open(next: { kind: "link" } | { kind: "unlink"; id: string }): void {
    confirming = next;
    password = "";
    code = "";
    refusal = null;
  }

  async function submit(): Promise<void> {
    if (!confirming || busy) return;
    busy = true;
    refusal = null;
    const target = confirming;
    try {
      const res = await fetch(target.kind === "link" ? LINK_START_PATH : identityPath(target.id), {
        method: target.kind === "link" ? "POST" : "DELETE",
        credentials: "same-origin",
        headers: writeHeaders(me.csrf),
        body: reauthBody(password, needsOtp ? code : null),
      });
      const body: unknown = await res.json().catch(() => null);
      refusal = readReauth(res.status, body);
      if (refusal) return;
      if (target.kind === "link") {
        const to = readLinkStart(body);
        if (to) return location.assign(to);
        refusal = { key: "m.acLinkFailed", detail: "", problems: [] };
        return;
      }
      confirming = null;
      onchanged("m.acUnlinked");
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    } finally {
      password = "";
      code = "";
      busy = false;
    }
  }
</script>

<h2>{t(prefs.lang, "m.acSso")}</h2>
<p class="dim">{t(prefs.lang, "m.acSsoNote")}</p>
{#if me.identities.length === 0}
  <p>{t(prefs.lang, "m.acSsoNone")}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>{t(prefs.lang, "m.acSsoIssuer")}</th>
        <th>{t(prefs.lang, "m.acSsoSubject")}</th>
        <th>{t(prefs.lang, "m.acSsoLinkedAt")}</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each me.identities as identity (identity.id)}
        <tr>
          <td><code>{identity.issuer}</code></td>
          <td><code>{identity.subject}</code></td>
          <td>{identity.linkedAt}</td>
          <td>
            {#if me.hasPassword}
              <button type="button" disabled={busy} onclick={() => open({ kind: "unlink", id: identity.id })}>{t(prefs.lang, "m.acSsoUnlink")}</button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if sso}
  {#if me.via === "password"}
    <p class="act"><button type="button" disabled={busy} onclick={() => open({ kind: "link" })}>{t(prefs.lang, "m.acSsoLink")}</button></p>
  {:else}
    <p class="dim">{t(prefs.lang, "m.acSsoLinkNeedsPassword")}</p>
  {/if}
{/if}

{#if confirming}
  <h3>{t(prefs.lang, "m.acReauthHeading")}</h3>
  {#if refusal}
    <RefusalNote {refusal} />
  {/if}
  <p class="dim">{t(prefs.lang, needsOtp ? "m.acReauthNoteOtp" : "m.acReauthNote")}</p>
  <form
    class="stack"
    onsubmit={(e) => {
      e.preventDefault();
      void submit();
    }}
  >
    <label>
      {t(prefs.lang, "m.acCurrent")}
      <input type="password" autocomplete="current-password" bind:value={password} required>
    </label>
    {#if needsOtp}
      <label>
        {t(prefs.lang, "m.otpCode")}
        <input class="otp" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" bind:value={code} required>
      </label>
    {/if}
    <p class="act">
      <button type="submit" disabled={busy}>{t(prefs.lang, "m.acReauthGo")}</button>
      <button type="button" onclick={() => (confirming = null)}>{t(prefs.lang, "m.cancel")}</button>
    </p>
  </form>
{/if}

<style>
  .stack { display: grid; gap: 12px; max-width: 440px; }
  .stack label { display: grid; gap: 4px; }
  .otp { font-family: var(--font-mono); letter-spacing: 0.2em; }
</style>
