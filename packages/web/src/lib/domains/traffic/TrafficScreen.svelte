<script lang="ts">
  import { onMount } from "svelte";
  import { directionWord, t } from "$lib/i18n";
  import { ageLabel } from "$lib/age";
  import { chromeFreshness } from "$lib/shell/freshness.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { loginHref } from "$lib/shell/who";
  import { trafficListing } from "./traffic";
  import { TRAFFIC_POLL_MS, trafficQuery } from "./query.svelte";

  const traffic = trafficQuery();
  const prefs = chromePrefs();
  const fresh = chromeFreshness();

  const stale = $derived(traffic.state.kind === "ok" && traffic.state.failCount > 0);
  const ageSec = $derived(
    traffic.state.kind === "ok" ? Math.max(0, Math.floor((fresh.now - traffic.state.lastOkAt) / 1000)) : 0,
  );
  const age = $derived(ageLabel(ageSec));

  $effect(() => {
    if (traffic.state.kind !== "ok") {
      fresh.publish(null);
      return;
    }
    fresh.publish({
      lastOkAt: traffic.state.lastOkAt,
      intervalMs: TRAFFIC_POLL_MS,
      failCount: traffic.state.failCount,
    });
    return () => fresh.publish(null);
  });

  onMount(() => {
    void traffic.refresh();
    const id = setInterval(() => void traffic.refresh(), TRAFFIC_POLL_MS);
    return () => clearInterval(id);
  });
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.traffic")}</title>
</svelte:head>

<h2>{t(prefs.lang, "m.trafficHeading")}</h2>
<p class="lede">
  {t(prefs.lang, "m.trafficLede")}
</p>

{#if traffic.state.kind === "loading"}
  <div class="empty-card">
    <p>{t(prefs.lang, "m.readingTraffic")}</p>
  </div>
{:else if traffic.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInTraffic")}</p>
  <p><a href={loginHref("/app/traffic")}>{t(prefs.lang, "m.signIn")}</a></p>
{:else if traffic.state.kind === "absent"}
  <div class="empty-card">
    <div class="lead">{t(prefs.lang, "m.trafficAbsent")}</div>
  </div>
{:else if traffic.state.kind === "error"}
  <div class="banner bad">
    <div class="lead">{t(prefs.lang, "m.trafficError", { message: traffic.state.message })}</div>
    <p class="act">
      <button type="button" onclick={() => void traffic.refresh()}>{t(prefs.lang, "m.reread")}</button>
    </p>
  </div>
{:else}
  {@const view = traffic.state.view}
  {@const listing = trafficListing(view)}
  {#if stale}
    <div class="banner warn hatch">
      <div class="lead">{t(prefs.lang, "m.staleBanner", { age })}</div>
      <div>
        {t(prefs.lang, "m.staleFails", { n: traffic.state.failCount, error: traffic.state.lastFail ?? "" })}
      </div>
      <p class="act">
        <button type="button" onclick={() => void traffic.refresh()}>{t(prefs.lang, "m.reread")}</button>
      </p>
    </div>
  {/if}

  {#if listing === "unavailable" && view.kind === "unavailable"}
    <div class="banner bad">
      <div class="lead">{view.message}</div>
    </div>
  {:else if listing === "empty"}
    <div class="empty-card">
      <div class="lead ok">{t(prefs.lang, "m.emptyTraffic")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyTrafficExplain")}</p>
    </div>
  {:else if view.kind === "summary"}
    {@const deadPct = view.entries === 0 ? 0 : Math.round((view.dead / view.entries) * 100)}
    <div class="stat-grid">
      <div class="stat-card loud">
        <div class="k">{t(prefs.lang, "m.deadCarried")}</div>
        <div class="v">{view.dead}</div>
        <p>{view.entries === 0 ? t(prefs.lang, "m.noEntries") : t(prefs.lang, "m.pctOf", { pct: deadPct, n: view.entries })}</p>
      </div>
      <div class="stat-card">
        <div class="k">{t(prefs.lang, "m.withTraffic")}</div>
        <div class="v" style="font-size:26px">{view.withTraffic}</div>
        <p>{t(prefs.lang, "m.somethingPassed")}</p>
      </div>
      <div class="stat-card">
        <div class="k">{t(prefs.lang, "m.entries")}</div>
        <div class="v" style="font-size:26px">{view.entries}</div>
        <p>{t(prefs.lang, "m.policyRows")}</p>
      </div>
    </div>

    <!-- Said out loud rather than left in the arithmetic. `entries` is now `withTraffic + dead`, so a
         row the server could not read is not in any of the three numbers above — and the headline
         percentage would otherwise be quietly about a smaller dump than the one that was taken. -->
    {#if view.unreadable > 0}
      <div class="empty-card">
        <div class="lead warn">{t(prefs.lang, "m.unreadableCounters", { n: view.unreadable })}</div>
      </div>
    {/if}

    {#if view.dead === 0}
      <div class="empty-card">
        <div class="lead ok">{t(prefs.lang, "m.emptyDead")}</div>
        <p class="dim">{t(prefs.lang, "m.emptyDeadExplain")}</p>
      </div>
    {:else if view.deadSample.length > 0}
      <h3>
        {t(prefs.lang, "m.deadSample")}
        <span class="chip warn">{t(prefs.lang, "m.truncated", { shown: view.deadSample.length, total: view.dead })}</span>
      </h3>
      <div class="scroll" class:stale-hold={stale}>
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.endpoint")}</th>
              <th>{t(prefs.lang, "c.dir")}</th>
              <th>{t(prefs.lang, "c.peer")}</th>
              <th>{t(prefs.lang, "c.port")}</th>
              <th>{t(prefs.lang, "c.packets")}</th>
              <th>{t(prefs.lang, "c.bytes")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.deadSample as row (`${row.endpoint}:${row.direction}:${row.peer}:${row.port}`)}
              <tr>
                <td class="mono">{row.endpoint}</td>
                <td>{directionWord(prefs.lang, row.direction)}</td>
                <td><code>{row.peer}</code></td>
                <td class="mono">{row.port}</td>
                <td class="num bad">{row.packets}</td>
                <td class="num dim">{row.bytes}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if view.top.length > 0}
      <h3>{t(prefs.lang, "m.whatPassed")}</h3>
      <p class="lede">{t(prefs.lang, "m.trafficBelow")}</p>
      <div class="scroll" class:stale-hold={stale}>
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.endpoint")}</th>
              <th>{t(prefs.lang, "c.dir")}</th>
              <th>{t(prefs.lang, "c.peer")}</th>
              <th>{t(prefs.lang, "c.port")}</th>
              <th>{t(prefs.lang, "c.packets")}</th>
              <th>{t(prefs.lang, "c.bytes")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.top as row (`${row.endpoint}:${row.direction}:${row.peer}:${row.port}`)}
              <tr>
                <td class="mono">{row.endpoint}</td>
                <td>{directionWord(prefs.lang, row.direction)}</td>
                <td><code>{row.peer}</code></td>
                <td class="mono">{row.port}</td>
                <td class="num">{row.packets}</td>
                <td class="num dim">{row.bytes}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
{/if}

<style>
  .stale-hold { opacity: 0.72; }
</style>
