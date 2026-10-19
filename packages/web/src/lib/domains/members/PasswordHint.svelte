<script lang="ts">
  // The rule as words, beside every new-password field. Only words: the server judges, and its
  // reasons arrive in `RefusalNote` when it refuses.
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";

  const prefs = chromePrefs();
</script>

<p class="dim hint">{t(prefs.lang, "m.mbPasswordHint")} {t(prefs.lang, "m.mbPasswordHintNote")}</p>

<style>
  .hint { margin: 0; font-size: 12px; }
</style>
