<script lang="ts">
  // One refusal: the translated sentence, then the server's own words and any password problems.
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import type { Refusal } from "./answer";

  let { refusal }: { refusal: Refusal } = $props();
  const prefs = chromePrefs();
</script>

<div class="banner bad" role="alert">
  <div class="lead">{t(prefs.lang, refusal.key)}</div>
  {#if refusal.problems.length > 0}
    <ul>
      {#each refusal.problems as problem, i (i)}
        <li>{problem}</li>
      {/each}
    </ul>
  {:else if refusal.detail}
    <p class="dim">{refusal.detail}</p>
  {/if}
</div>
