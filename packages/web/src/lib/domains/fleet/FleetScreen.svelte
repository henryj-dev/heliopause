<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import Chip from "$lib/shell/Chip.svelte";
  import { chromeFreshness } from "$lib/shell/freshness.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { ageLabel } from "$lib/age";
  import {
    answeredVpcNames, fleetListing, fleetSummary, hostMatches, hostRowClass, hostsOnVpc, hostStateChips,
    membershipPodCount, routesView, vpcLabel, vpcTone, wantedGeneration, whyBits, workloadChip,
  } from "./present";
  import { FLEET_POLL_MS, fleetQuery } from "./query.svelte";

  const fleet = fleetQuery();
  const prefs = chromePrefs();
  const fresh = chromeFreshness();
  let filter = $state("");

  const ageSec = $derived(
    fleet.state.kind === "ok" ? Math.max(0, Math.floor((fresh.now - fleet.state.lastOkAt) / 1000)) : 0,
  );
  const age = $derived(ageLabel(ageSec));

  $effect(() => {
    if (fleet.state.kind !== "ok") {
      fresh.publish(null);
      return;
    }
    fresh.publish({
      lastOkAt: fleet.state.lastOkAt,
      intervalMs: FLEET_POLL_MS,
      failCount: fleet.state.failCount,
    });
    return () => fresh.publish(null);
  });

  onMount(() => {
    void fleet.refresh();
    const id = setInterval(() => void fleet.refresh(), FLEET_POLL_MS);
    return () => clearInterval(id);
  });
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.fleet")}</title>
</svelte:head>

<p class="lede">{t(prefs.lang, "m.fleetLede")}</p>

{#if fleet.state.kind === "loading"}
  <p>{t(prefs.lang, "m.readingSite")}</p>
{:else if fleet.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInFleet")}</p>
  <p><a href="/auth/login?next=/app">{t(prefs.lang, "m.signIn")}</a></p>
{:else if fleet.state.kind === "error"}
  <p>{t(prefs.lang, "m.siteError", { message: fleet.state.message })}</p>
{:else}
  {@const site = fleet.state.site}
  {@const summary = fleetSummary(site)}
  {@const listing = fleetListing(site)}
  {@const shown = site.hosts.filter((host) => hostMatches(host, filter))}
  {@const reachAll = site.reachable === site.asked}
  {@const wanted = wantedGeneration(site.hosts)}
  {@const stale = fleet.state.failCount > 0}
  {@const answered = answeredVpcNames(site)}

  {#if stale}
    <div class="banner warn hatch">
      <div class="lead">{t(prefs.lang, "m.staleBanner", { age })}</div>
      <div>
        {t(prefs.lang, "m.staleFails", { n: fleet.state.failCount, error: fleet.state.lastFail ?? "" })}
      </div>
      <p class="act">
        <button type="button" onclick={() => void fleet.refresh()}>{t(prefs.lang, "m.reread")}</button>
      </p>
    </div>
  {/if}

  {#if site.problems.length > 0}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.problemsLead", { n: site.problems.length })}</div>
      {#each site.problems as line (line)}
        <div>· {line}</div>
      {/each}
    </div>
  {/if}

  <div class="vpc-strip">
    {#each site.vpcs as vpc (vpc.name)}
      {@const tone = vpcTone(vpc, site.hosts)}
      <div class="vpc-card {tone}" class:hatch={!vpc.ok}>
        <div class="hd">
          <span>{vpc.name}</span>
          <span class={tone === "ok" ? "ok" : tone === "warn" ? "warn" : "bad"}>{vpcLabel(vpc, site.hosts, prefs.lang)}</span>
        </div>
        <div class="meta">
          {#if vpc.ok}
            {t(prefs.lang, "m.hostsOnVpc", { n: hostsOnVpc(site.hosts, vpc.name) })}
          {:else}
            {vpc.error}
            <div>{t(prefs.lang, "m.vpcHidden")}</div>
          {/if}
        </div>
      </div>
    {/each}
  </div>

  <div class="summary-row">
    <span class="stat {reachAll ? 'ok' : 'bad'}">{t(prefs.lang, "m.answered", { reachable: site.reachable, asked: site.asked })}</span>
    <span class="stat {summary.generations.length > 1 ? 'warn' : ''}">
      {#if summary.generations.length === 0}
        {t(prefs.lang, "m.noGeneration")}
      {:else if summary.generations.length === 1}
        {t(prefs.lang, "m.oneGeneration", { id: summary.generations[0] ?? "" })}
      {:else}
        {t(prefs.lang, "m.generationsInPlay", { n: summary.generations.length })}
      {/if}
    </span>
    <span class="stat {summary.problems > 0 ? 'bad' : ''}">{t(prefs.lang, "m.problemCount", { n: summary.problems })}</span>
    <span style="flex:1"></span>
    {#if listing === "hosts"}
      <input bind:value={filter} placeholder={t(prefs.lang, "m.filterHosts")} size="22">
    {/if}
  </div>

  {#if listing === "empty"}
    <div class="empty-card">
      <div class="ok">{t(prefs.lang, "m.emptyAnswered", { name: answered.join(", ") || "—" })}</div>
      <p class="dim">{t(prefs.lang, "m.emptyExplain")}</p>
      <p><a href="{base}/enrollment">{t(prefs.lang, "m.emptyEnroll")}</a></p>
    </div>
  {:else if listing === "hosts"}
    <div class="scroll" class:stale-hold={stale}>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.host")}</th>
            <th>{t(prefs.lang, "c.state")}</th>
            <th>{t(prefs.lang, "c.generation")}</th>
            <th>
              {t(prefs.lang, "c.heartbeat")}
              {#if stale}
                ({t(prefs.lang, "m.asOf", { age })})
              {/if}
            </th>
            <th>{t(prefs.lang, "c.stage")}</th>
            <th>{t(prefs.lang, "c.why")}</th>
            <th>{t(prefs.lang, "c.workload")}</th>
            <th>{t(prefs.lang, "c.routes")}</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as host (host.vpc + host.host)}
            {@const chips = hostStateChips(host, prefs.lang)}
            {@const why = whyBits(host, prefs.lang)}
            {@const routes = routesView(host)}
            <tr class={hostRowClass(host)}>
              <td>
                <span class="name">{host.host}</span>
                <span class="dim mono"> {host.vpc}</span>
              </td>
              <td>
                <div class="chips">
                  {#each chips as chip (`${chip.kind}:${chip.word}`)}
                    <Chip kind={chip.kind} hatch={chip.hatch}>{chip.word}</Chip>
                  {/each}
                  {#if stale}
                    <Chip kind="mute">{t(prefs.lang, "m.stale")}</Chip>
                  {/if}
                </div>
              </td>
              <td>
                {#if host.generation}
                  <span class="mono">{host.generation}</span>
                  {#if host.current}
                    <span class="ok"> {t(prefs.lang, "m.wantedEq")}</span>
                  {:else}
                    <span class="warn"> {t(prefs.lang, "m.wantedNeq")}{#if wanted} {wanted}{/if}</span>
                  {/if}
                {:else}
                  <Chip kind="none">{t(prefs.lang, "m.unreported")}</Chip>
                {/if}
              </td>
              <td>
                {#if host.ageSec === null}
                  <Chip kind="none">{t(prefs.lang, "m.unreported")}</Chip>
                {:else}
                  <span class="num">{host.ageSec}s</span>
                {/if}
              </td>
              <td class="mono">{host.stage ?? "—"}</td>
              <td>
                {#if why.length === 0}
                  <span class="dim">—</span>
                {:else}
                  {#each why as bit (bit)}
                    <div>{bit}</div>
                  {/each}
                {/if}
              </td>
              <td>
                {#if !host.workload}
                  <span class="dim">—</span>
                {:else}
                  {@const work = host.workload}
                  {@const wchip = workloadChip(work, prefs.lang)}
                  <div>
                    <span class="mono">{work.cluster}</span>
                    · <Chip kind={wchip.kind} hatch={wchip.hatch}>{wchip.word}</Chip>
                  </div>
                  {#if host.state === "confirmed" && work.state === "rolled-back"}
                    <div class="dim">{t(prefs.lang, "m.hostOkWorkloadRolled")}</div>
                  {/if}
                  {#if work.membership}
                    <div class="dim">
                      {t(prefs.lang, "m.podsExpected", { n: membershipPodCount(work.membership), expected: work.expected })}
                      · {work.membership.at}
                    </div>
                  {/if}
                {/if}
              </td>
              <td>
                {#if routes.kind === "unreported"}
                  <Chip kind="none">{t(prefs.lang, "m.unreported")}</Chip>
                {:else if routes.kind === "owned"}
                  <span class="num dim">{routes.total}</span>
                {:else}
                  <span class="warn" title={routes.title}>{t(prefs.lang, "m.byHand", { n: routes.hand })}</span>
                  <span class="dim"> / {routes.total}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if shown.length === 0}
      <p>{t(prefs.lang, "m.noneMatch")}</p>
    {/if}
    {#if stale}
      <p class="dim">{t(prefs.lang, "m.staleFoot")}</p>
    {/if}
  {/if}
{/if}

<style>
  .empty-card {
    border: 1px solid var(--bd-1);
    background: var(--surface-card);
    border-radius: var(--r-md);
    padding: 26px;
    text-align: center;
  }
  .empty-card .ok { font-family: var(--font-mono); font-size: 13px; font-weight: 600; }
  .stale-hold { opacity: 0.72; }
</style>
