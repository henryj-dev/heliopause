<script lang="ts">
  // The change-password form. Repeat is checked here; length and kinds are the server's to judge.
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { writeHeaders } from "./write";
  import { readPasswordChange, repeatProblem, type Refusal } from "./answer";
  import { ME_PASSWORD_PATH, passwordChangeBody } from "./account";
  import PasswordHint from "./PasswordHint.svelte";
  import RefusalNote from "./RefusalNote.svelte";

  let { csrf, onchanged }: { csrf: string | null; onchanged: (endedSessions: number) => void } = $props();

  const prefs = chromePrefs();
  let current = $state("");
  let next = $state("");
  let repeat = $state("");
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);

  async function submit(): Promise<void> {
    const problem = repeatProblem(next, repeat);
    if (problem) {
      refusal = { key: problem, detail: "", problems: [] };
      return;
    }
    busy = true;
    refusal = null;
    try {
      const res = await fetch(ME_PASSWORD_PATH, {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf),
        body: passwordChangeBody(current, next),
      });
      const body: unknown = await res.json().catch(() => null);
      refusal = readPasswordChange(res.status, body);
      if (!refusal) {
        current = next = repeat = "";
        const ended = typeof (body as { endedSessions?: unknown })?.endedSessions === "number"
          ? (body as { endedSessions: number }).endedSessions : 0;
        onchanged(ended);
      }
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    } finally {
      busy = false;
    }
  }
</script>

<h2>{t(prefs.lang, "m.acChangeHeading")}</h2>
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
    {t(prefs.lang, "m.acCurrent")}
    <input type="password" autocomplete="current-password" bind:value={current} required>
  </label>
  <label>
    {t(prefs.lang, "m.acNext")}
    <input type="password" autocomplete="new-password" bind:value={next} required>
  </label>
  <label>
    {t(prefs.lang, "m.acRepeat")}
    <input type="password" autocomplete="new-password" bind:value={repeat} required>
  </label>
  <PasswordHint />
  <p class="act">
    <button type="submit" disabled={busy}>{t(prefs.lang, "m.acChangeSubmit")}</button>
  </p>
</form>

<style>
  .stack { display: grid; gap: 12px; max-width: 440px; }
  .stack label { display: grid; gap: 4px; }
</style>
