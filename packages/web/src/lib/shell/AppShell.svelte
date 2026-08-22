<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { page } from "$app/state";
  import { crumbLabel, t } from "../i18n.ts";
  import { GROUP_I18N, NAV_I18N, activeKey, crumbsFor, navGroups } from "./nav";
  import { ageLabel } from "../age.ts";
  import { chromeFreshness } from "./freshness.svelte";
  import { chromePrefs } from "./prefs.svelte";
  import { loginHref, mayLabel, viaLabel } from "./who";
  import { WHO_POLL_MS, whoQuery } from "./who.svelte";
  import "./tokens.css";
  import "./base.css";
  import "./chrome.css";

  let { children } = $props();

  const groups = navGroups();
  const prefs = chromePrefs();
  const who = whoQuery();
  const fresh = chromeFreshness();
  const key = $derived(activeKey(page.url.pathname, base));
  const crumbs = $derived(crumbsFor(key, page.url.pathname, base));
  const next = $derived(`${page.url.pathname}${page.url.search}`);
  const freshAge = $derived(
    fresh.snap ? ageLabel(Math.max(0, Math.floor((fresh.now - fresh.snap.lastOkAt) / 1000))) : "",
  );

  const pendingPlans = $derived(who.state.kind === "ok" ? who.state.view.pendingPlans : 0);
  const pendingCsrs = $derived(who.state.kind === "ok" ? who.state.view.pendingCsrs : 0);

  onMount(() => {
    void who.refresh();
    const id = setInterval(() => void who.refresh(), WHO_POLL_MS);
    return () => clearInterval(id);
  });
</script>

<div class="app-edge" aria-hidden="true"></div>
<div class="app">
  <header class="topbar">
    <a class="tb-brand" href="{base}/fleet" aria-label={t(prefs.lang, "page.home")}>
      <span aria-hidden="true">▪</span><span>heliopause</span>
    </a>
    <span class="tb-divider" aria-hidden="true"></span>
    <div class="tb-crumbs">
      {#each crumbs as crumb, i (crumb + i)}
        {#if i > 0}<span class="sep">/</span>{/if}
        <span class={i === crumbs.length - 1 ? "cur" : ""}>{crumbLabel(prefs.lang, crumb)}</span>
      {/each}
    </div>
    <div class="tb-right">
      {#if fresh.snap}
        <span class="tb-fresh" class:stale={fresh.snap.failCount > 0}>
          {#if fresh.snap.failCount === 0}
            <span class="tb-dot" aria-hidden="true"></span>
          {/if}
          {t(prefs.lang, "m.readAgo", { age: freshAge })}
          · {t(prefs.lang, "m.pollEvery", { n: fresh.snap.intervalMs / 1000 })}
          · {t(prefs.lang, "m.failCount", { n: fresh.snap.failCount })}
        </span>
      {/if}
      {#if who.state.kind === "ok"}
        {@const view = who.state.view}
        <span class="tb-who">
          {view.you} · {viaLabel(view.csrf, prefs.lang)} · {mayLabel(view.canWrite, prefs.lang)}
          {#if view.csrf}
            ·
            <button type="button" class="tb-who-out" onclick={() => void who.signOut()}>
              {t(prefs.lang, "m.signOut")}
            </button>
          {/if}
        </span>
      {:else if who.state.kind === "unauth"}
        <span class="tb-who">
          <a href={loginHref(next)}>{t(prefs.lang, "m.signIn")}</a>
        </span>
      {/if}
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

  <aside class="sb">
    <nav class="sb-nav" aria-label={t(prefs.lang, "g.sections")}>
      {#each groups as group (group.label)}
        <div class="sb-section">{t(prefs.lang, GROUP_I18N[group.label] ?? "g.fleet")}</div>
        {#each group.items as item (item.key)}
          {@const href = `${base}${item.href}`}
          <a href={href} class="sb-item" aria-current={key === item.key ? "page" : undefined}>
            {t(prefs.lang, NAV_I18N[item.key] ?? "nav.fleet")}
            {#if item.key === "changes" && pendingPlans > 0}
              <span class="n">{t(prefs.lang, "m.pendingWaiting", { n: pendingPlans })}</span>
            {:else if item.key === "enrollment" && pendingCsrs > 0}
              <span class="n">{t(prefs.lang, "m.pendingWaiting", { n: pendingCsrs })}</span>
            {/if}
          </a>
        {/each}
      {/each}
    </nav>
  </aside>

  <main class="main">
    <div class="content">
      <div class="page">
        {@render children()}
      </div>
    </div>
  </main>
</div>
