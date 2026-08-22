<script lang="ts">
  import { onMount, untrack } from "svelte";
  import { actionWord, layerWord, protoWord, t, whereWord } from "$lib/i18n";
  import { ageLabel } from "$lib/age";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { loginHref } from "$lib/shell/who";
  import {
    coveringUsages,
    exactUsages,
    remainingUndecidable,
    verdictWhy,
    type LookupHit,
  } from "./lookup";
  import { lookupQuery, whereUsedQuery } from "./query.svelte";

  const lookup = lookupQuery();
  const whereUsed = whereUsedQuery();
  const prefs = chromePrefs();

  let src = $state("");
  let dst = $state("");
  let srcWorkload = $state("");
  let dstWorkload = $state("");
  let port = $state("");
  let proto = $state("tcp");
  let written = $state("");

  onMount(() => {
    void whereUsed.run("");
  });

  function askLookup(): void {
    void lookup.run({ src, dst, srcWorkload, dstWorkload, port, proto, lang: prefs.lang });
  }

  // Why sentences live on the payload. Switching language without a refetch
  // would leave the previous language's reasons on the table.
  $effect(() => {
    const lang = prefs.lang;
    untrack(() => lookup.replayLang(lang));
  });

  function ageOf(lastOkAt: number): string {
    return ageLabel(Math.max(0, Math.floor((Date.now() - lastOkAt) / 1000)));
  }

  function hitWhy(hit: LookupHit): string {
    const why = [verdictWhy(hit.src), verdictWhy(hit.dst), verdictWhy(hit.port), verdictWhy(hit.proto_)]
      .filter(Boolean)
      .join(" · ");
    return why ? `${hit.name} — ${why}` : hit.name;
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.lookup")}</title>
</svelte:head>

<p class="lede">
  {t(prefs.lang, "m.lookupLede")}
</p>

<div class="lookup-grid">
<section class="ask-card">
  <h2>{t(prefs.lang, "m.lookupFlow")}</h2>
  <p class="dim">{t(prefs.lang, "m.lookupFlowHint")}</p>
  <form
    onsubmit={(ev) => {
      ev.preventDefault();
      askLookup();
    }}
  >
    <div class="field-grid" style="width:100%">
      <label class="field"><span>{t(prefs.lang, "m.fieldSrc")}</span><input bind:value={src}></label>
      <label class="field"><span>{t(prefs.lang, "m.fieldDst")}</span><input bind:value={dst}></label>
      <div style="display:flex;gap:8px">
        <label class="field" style="flex:1"><span>{t(prefs.lang, "c.port")}</span><input bind:value={port} inputmode="numeric"></label>
        <label class="field" style="flex:1">
          <span>{t(prefs.lang, "c.proto")}</span>
          <select bind:value={proto}>
            <option value="tcp">{protoWord(prefs.lang, "tcp")}</option>
            <option value="udp">{protoWord(prefs.lang, "udp")}</option>
            <option value="icmp">{protoWord(prefs.lang, "icmp")}</option>
            <option value="any">{protoWord(prefs.lang, "any")}</option>
          </select>
        </label>
      </div>
      <label class="field"><span>{t(prefs.lang, "m.fieldSrcWorkload")}</span><input bind:value={srcWorkload} placeholder={t(prefs.lang, "m.workloadPlaceholder")}></label>
      <label class="field"><span>{t(prefs.lang, "m.fieldDstWorkload")}</span><input bind:value={dstWorkload} placeholder={t(prefs.lang, "m.workloadPlaceholder")}></label>
      <button type="submit" style="align-self:end" disabled={lookup.running}>{t(prefs.lang, "m.lookUp")}</button>
    </div>
  </form>
  <div class="caveat">
    {t(prefs.lang, "m.lookupCaveat")}
  </div>

  {#if lookup.state.kind === "loading"}
    <p>{t(prefs.lang, "m.lookingUp")}</p>
  {:else if lookup.state.kind === "unauth"}
    <p>{t(prefs.lang, "m.signInLookup")}</p>
    <p><a href={loginHref("/app/lookup")}>{t(prefs.lang, "m.signIn")}</a></p>
  {:else if lookup.state.kind === "absent"}
    <div class="empty-card">
      <div class="lead">{t(prefs.lang, "m.noPolicyRepo")}</div>
    </div>
  {:else if lookup.state.kind === "error"}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.lookupError", { message: lookup.state.message })}</div>
    </div>
  {:else if lookup.state.kind === "ok"}
    {@const view = lookup.state.view}
    {@const rest = remainingUndecidable(view.undecidable)}
    {#if lookup.state.failCount > 0}
      <div class="banner warn hatch">
        <div class="lead">{t(prefs.lang, "m.staleBanner", { age: ageOf(lookup.state.lastOkAt) })}</div>
        <div>
          {t(prefs.lang, "m.staleFails", { n: lookup.state.failCount, error: lookup.state.lastFail ?? "" })}
        </div>
      </div>
    {/if}
    <div class="caveat">
      {t(prefs.lang, "m.lookupAt", { id: view.generation ?? t(prefs.lang, "m.unreported") })}
      {#if view.dirty}
        <span class="chip warn">{t(prefs.lang, "m.dirtyEdits")}</span>
      {/if}
      · {t(prefs.lang, "m.enabledRules", { n: view.considered })}
    </div>
    {#if view.matches.length === 0}
      <div class="empty-card">
        <div class="lead ok">{t(prefs.lang, "m.lookupNone")}</div>
      </div>
    {:else}
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.id")}</th>
            <th>{t(prefs.lang, "c.action")}</th>
            <th>{t(prefs.lang, "c.layer")}</th>
            <th>{t(prefs.lang, "c.proto")}</th>
            <th>{t(prefs.lang, "c.ports")}</th>
            <th>{t(prefs.lang, "c.pri")}</th>
            <th>{t(prefs.lang, "c.why")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.matches as hit (hit.id)}
            <tr>
              <td>{hit.id}</td>
              <td>{actionWord(prefs.lang, hit.action)}</td>
              <td>{layerWord(prefs.lang, hit.layer)}</td>
              <td>{hit.proto}</td>
              <td>{hit.ports || t(prefs.lang, "v.any")}</td>
              <td>{hit.priority}</td>
              <td>{hitWhy(hit)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if view.needsWorkload > 0}
      <p>
        {t(prefs.lang, "m.needsWorkload", { n: view.needsWorkload })}
      </p>
    {/if}
    {#if rest.length > 0}
      <h3>{t(prefs.lang, "m.undecidable")}</h3>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.id")}</th>
            <th>{t(prefs.lang, "c.action")}</th>
            <th>{t(prefs.lang, "c.layer")}</th>
            <th>{t(prefs.lang, "c.proto")}</th>
            <th>{t(prefs.lang, "c.ports")}</th>
            <th>{t(prefs.lang, "c.pri")}</th>
            <th>{t(prefs.lang, "c.why")}</th>
          </tr>
        </thead>
        <tbody>
          {#each rest as hit (hit.id)}
            <tr>
              <td>{hit.id}</td>
              <td>{actionWord(prefs.lang, hit.action)}</td>
              <td>{layerWord(prefs.lang, hit.layer)}</td>
              <td>{hit.proto}</td>
              <td>{hit.ports || t(prefs.lang, "v.any")}</td>
              <td>{hit.priority}</td>
              <td>{hitWhy(hit)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>

<section class="ask-card">
  <h2>{t(prefs.lang, "m.lookupWritten")}</h2>
  <p class="dim">{t(prefs.lang, "m.lookupWrittenHint")}</p>
  <form
    onsubmit={(ev) => {
      ev.preventDefault();
      void whereUsed.run(written);
    }}
  >
    <label class="field" style="flex:1">
      <span>{t(prefs.lang, "m.fieldQuery")}</span>
      <input bind:value={written} placeholder={t(prefs.lang, "m.wherePlaceholder")}>
    </label>
    <button type="submit" disabled={whereUsed.running}>{t(prefs.lang, "m.find")}</button>
  </form>

  {#if whereUsed.state.kind === "loading"}
    <p>{t(prefs.lang, "m.lookingUp")}</p>
  {:else if whereUsed.state.kind === "unauth"}
    <p>{t(prefs.lang, "m.signInWhere")}</p>
    <p><a href={loginHref("/app/lookup")}>{t(prefs.lang, "m.signIn")}</a></p>
  {:else if whereUsed.state.kind === "absent"}
    <div class="empty-card">
      <div class="lead">{t(prefs.lang, "m.noPolicyRepo")}</div>
    </div>
  {:else if whereUsed.state.kind === "error"}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.searchError", { message: whereUsed.state.message })}</div>
    </div>
  {:else}
    {@const view = whereUsed.state.view}
    {@const exact = exactUsages(view.usages)}
    {@const covering = coveringUsages(view.usages)}
    {#if whereUsed.state.failCount > 0}
      <div class="banner warn hatch">
        <div class="lead">{t(prefs.lang, "m.staleBanner", { age: ageOf(whereUsed.state.lastOkAt) })}</div>
        <div>
          {t(prefs.lang, "m.staleFails", { n: whereUsed.state.failCount, error: whereUsed.state.lastFail ?? "" })}
        </div>
      </div>
    {/if}
    <p>{t(prefs.lang, "m.rulesAt", { n: view.considered, id: view.generation ?? "?" })}</p>
    {#if view.query}
      {#if exact.length === 0}
        <div class="empty-card">
          <div class="lead ok">{t(prefs.lang, "m.noRuleWrites")}</div>
        </div>
      {:else}
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.id")}</th>
              <th>{t(prefs.lang, "c.where")}</th>
              <th>{t(prefs.lang, "c.text")}</th>
              <th>{t(prefs.lang, "c.action")}</th>
              <th>{t(prefs.lang, "c.layer")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each exact as row (`${row.policyId}:${row.where}:${row.text}`)}
              <tr>
                <td>{row.policyId}</td>
                <td>{whereWord(prefs.lang, row.where)}</td>
                <td><code>{row.text}</code></td>
                <td>{actionWord(prefs.lang, row.action)}</td>
                <td>{layerWord(prefs.lang, row.layer)}</td>
                <td>{row.enabled ? "" : t(prefs.lang, "m.disabled")}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
      {#if covering.length > 0}
        <h3>{t(prefs.lang, "m.coveringRanges")}</h3>
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.id")}</th>
              <th>{t(prefs.lang, "c.where")}</th>
              <th>{t(prefs.lang, "c.text")}</th>
              <th>{t(prefs.lang, "c.action")}</th>
              <th>{t(prefs.lang, "c.layer")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each covering as row (`${row.policyId}:${row.where}:${row.text}`)}
              <tr>
                <td>{row.policyId}</td>
                <td>{whereWord(prefs.lang, row.where)}</td>
                <td><code>{row.text}</code></td>
                <td>{actionWord(prefs.lang, row.action)}</td>
                <td>{layerWord(prefs.lang, row.layer)}</td>
                <td>{row.enabled ? "" : t(prefs.lang, "m.disabled")}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {/if}
    {#if view.repeated.length > 0}
      <h3>{t(prefs.lang, "m.repeated")}</h3>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.literal")}</th>
            <th>{t(prefs.lang, "c.rules")}</th>
            <th>{t(prefs.lang, "c.where")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.repeated as row (row.value)}
            <tr>
              <td><code>{row.value}</code></td>
              <td>{row.count}</td>
              <td>{row.policyIds.join(" ")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>
</div>
