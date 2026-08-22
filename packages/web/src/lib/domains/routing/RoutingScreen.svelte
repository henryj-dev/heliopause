<script lang="ts">
  import { onMount } from "svelte";
  import { originWord, t, type Lang } from "$lib/i18n";
  import { ageLabel } from "$lib/age";
  import { chromeFreshness } from "$lib/shell/freshness.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { loginHref } from "$lib/shell/who";
  import { hostIsClean, routingListing, type RouteVerdict, type RoutingHost } from "./routing";
  import { ROUTING_POLL_MS, routingQuery } from "./query.svelte";

  const routing = routingQuery();
  const prefs = chromePrefs();
  const fresh = chromeFreshness();

  const stale = $derived(routing.state.kind === "ok" && routing.state.failCount > 0);
  const ageSec = $derived(
    routing.state.kind === "ok" ? Math.max(0, Math.floor((fresh.now - routing.state.lastOkAt) / 1000)) : 0,
  );
  const age = $derived(ageLabel(ageSec));

  $effect(() => {
    if (routing.state.kind !== "ok") {
      fresh.publish(null);
      return;
    }
    fresh.publish({
      lastOkAt: routing.state.lastOkAt,
      intervalMs: ROUTING_POLL_MS,
      failCount: routing.state.failCount,
    });
    return () => fresh.publish(null);
  });

  onMount(() => {
    void routing.refresh();
    const id = setInterval(() => void routing.refresh(), ROUTING_POLL_MS);
    return () => clearInterval(id);
  });

  function hostSummary(host: RoutingHost, lang: Lang): string {
    if (hostIsClean(host)) return t(lang, "m.routingClean");
    const parts: string[] = [];
    if (host.missing > 0) parts.push(t(lang, "m.routingMissing", { n: host.missing }));
    if (host.undeclared > 0) parts.push(t(lang, "m.routingUndeclared", { n: host.undeclared }));
    if (host.unstated > 0) parts.push(t(lang, "m.routingUnstated", { n: host.unstated }));
    return parts.join(" · ");
  }

  function verdictLabel(verdict: RouteVerdict, lang: Lang): string {
    if (verdict === "ok") return t(lang, "v.ok");
    if (verdict === "missing") return t(lang, "v.missing");
    if (verdict === "undeclared") return t(lang, "v.undeclared");
    if (verdict === "unstated") return t(lang, "v.unstated");
    return t(lang, "v.automatic");
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.routing")}</title>
</svelte:head>

<p class="lede">
  {t(prefs.lang, "m.routingLede")}
</p>

{#if routing.state.kind === "loading"}
  <div class="empty-card">
    <p>{t(prefs.lang, "m.readingRoutes")}</p>
  </div>
{:else if routing.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInRouting")}</p>
  <p><a href={loginHref("/app/routing")}>{t(prefs.lang, "m.signIn")}</a></p>
{:else if routing.state.kind === "absent"}
  <div class="empty-card">
    <div class="lead">{t(prefs.lang, "m.routingNone")}</div>
  </div>
{:else if routing.state.kind === "error"}
  <div class="banner bad">
    <div class="lead">{t(prefs.lang, "m.routingError", { message: routing.state.message })}</div>
    <p class="act">
      <button type="button" onclick={() => void routing.refresh()}>{t(prefs.lang, "m.reread")}</button>
    </p>
  </div>
{:else}
  {@const view = routing.state.view}
  {@const listing = routingListing(view)}
  {#if stale}
    <div class="banner warn hatch">
      <div class="lead">{t(prefs.lang, "m.staleBanner", { age })}</div>
      <div>
        {t(prefs.lang, "m.staleFails", { n: routing.state.failCount, error: routing.state.lastFail ?? "" })}
      </div>
      <p class="act">
        <button type="button" onclick={() => void routing.refresh()}>{t(prefs.lang, "m.reread")}</button>
      </p>
    </div>
  {/if}

  {#if listing === "empty"}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyRoutes")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyRoutesExplain")}</p>
    </div>
  {:else}
    <div class:stale-hold={stale}>
    {#each view.hosts as host (host.vpc + host.host)}
      <h3>{host.host} <span>{host.vpc}</span></h3>
      {#if host.rows === null}
        <p class="caveat">{t(prefs.lang, "m.routingNoModel")}</p>
      {:else}
        <p>
          {#if hostIsClean(host)}
            <span class="chip ok">{hostSummary(host, prefs.lang)}</span>
          {:else}
            <span class="chip warn">{hostSummary(host, prefs.lang)}</span>
          {/if}
        </p>
        <div class="scroll">
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.dst")}</th>
              <th>{t(prefs.lang, "c.via")}</th>
              <th>{t(prefs.lang, "c.dev")}</th>
              <th>{t(prefs.lang, "c.table")}</th>
              <th>{t(prefs.lang, "c.verdict")}</th>
              <th>{t(prefs.lang, "c.owner")}</th>
              <th>{t(prefs.lang, "c.origin")}</th>
              <th>{t(prefs.lang, "c.why")}</th>
            </tr>
          </thead>
          <tbody>
            {#each host.rows as row (`${row.table}:${row.dst}:${row.via}:${row.dev}:${row.verdict}`)}
              <tr>
                <td><code>{row.dst}</code></td>
                <td><code>{row.via}</code></td>
                <td>{row.dev}</td>
                <td>{row.table}</td>
                <td>
                  <span class="chip {row.verdict === 'ok' ? 'ok' : row.verdict === 'missing' ? 'bad' : row.verdict === 'undeclared' ? 'warn' : 'mute'}">
                    {verdictLabel(row.verdict, prefs.lang)}
                  </span>
                </td>
                <td>{row.owner}</td>
                <td>{originWord(prefs.lang, row.origin)}</td>
                <td>{row.note}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        </div>
      {/if}
    {/each}
    </div>
  {/if}
  <p>
    {view.generation ? t(prefs.lang, "m.generationId", { id: view.generation }) : t(prefs.lang, "m.generationNone")}
    {#if view.dirty}
      · {t(prefs.lang, "m.uncommitted")}
    {/if}
  </p>
{/if}

<style>
  .stale-hold { opacity: 0.72; }
</style>
