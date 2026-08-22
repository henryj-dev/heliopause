<script lang="ts">
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { shortDigest } from "./present";
  import type { RequestRow } from "./store";

  let { request }: { request: RequestRow } = $props();
  const prefs = chromePrefs();
  let open = $state(false);
  let copied = $state(false);

  async function copyDigest(): Promise<void> {
    try {
      await navigator.clipboard.writeText(request.csrSha256);
      copied = true;
    } catch {
      copied = false;
    }
  }
</script>

<div class="csr-pane">
  <p class="act">
    {t(prefs.lang, "m.csrSha")}
    <code title={request.csrSha256}>{shortDigest(request.csrSha256)}</code>
    <button type="button" onclick={() => void copyDigest()}>
      {copied ? t(prefs.lang, "m.csrCopied") : t(prefs.lang, "m.copyCsr")}
    </button>
    <button type="button" onclick={() => (open = !open)}>
      {open ? t(prefs.lang, "m.hideCsr") : t(prefs.lang, "m.showCsr")}
    </button>
  </p>
  {#if open}
    <p class="dim">{t(prefs.lang, "m.csrPemNote")}</p>
    <pre>{request.csrPem}</pre>
  {/if}
</div>

<style>
  .csr-pane pre { max-height: 240px; }
</style>
