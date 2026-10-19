<script lang="ts">
  // The frame for the pages a signed-out browser uses (sign-in, invitation, reset): the same bar,
  // no menu, and no `/api/authz` poll — there is nobody to ask about yet.
  import { base } from "$app/paths";
  import { t } from "../i18n.ts";
  import { chromePrefs } from "./prefs.svelte";
  import "./tokens.css";
  import "./base.css";
  import "./chrome.css";

  let { children } = $props();
  const prefs = chromePrefs();
</script>

<div class="app-edge" aria-hidden="true"></div>
<div class="app public">
  <header class="topbar">
    <a class="tb-brand" href="{base}/login" aria-label={t(prefs.lang, "page.home")}>
      <span aria-hidden="true">▪</span><span>heliopause</span>
    </a>
    <span class="tb-divider" aria-hidden="true"></span>
    <div class="tb-crumbs"><span class="cur">{t(prefs.lang, "g.account")}</span></div>
    <div class="tb-right">
      <button
        type="button"
        class="tb-icon"
        onclick={() => prefs.cycleTheme()}
        title={t(prefs.lang, "page.theme", { theme: prefs.theme })}
        aria-label={t(prefs.lang, "page.cycleTheme")}
      >
        {prefs.theme === "dark" ? "☀" : prefs.theme === "light" ? "☾" : "◐"}
      </button>
      <span class="langs">
        <button type="button" class:on={prefs.lang === "ko"} onclick={() => prefs.setLang("ko")}>ko</button>
        <button type="button" class:on={prefs.lang === "en"} onclick={() => prefs.setLang("en")}>en</button>
      </span>
    </div>
  </header>

  <main class="main">
    <div class="content">
      <div class="page narrow">
        {@render children()}
      </div>
    </div>
  </main>
</div>

<style>
  .app.public { grid-template-columns: minmax(0, 1fr); }
  .narrow { max-width: 440px; }
</style>
