<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { base } from "$app/paths";
  import { actionWord, denyModeWord, t } from "$lib/i18n";
  import Chip from "$lib/shell/Chip.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import "./rows.css";
  import { ALL_SECTION, presentSections, resolveSection, sectionLabel, sectionPath, type PolicySectionId } from "./sections";
  import PolicyWrite from "./PolicyWrite.svelte";
  import { policyQuery } from "./query.svelte";
  import { coverageKind, placement, policyFindings, policyRowClass, riskKind, riskLabel, sourceCell } from "./present";
  import type { CoverageCellView } from "./screen";

  let { asked }: { asked: string } = $props();

  const policy = policyQuery();
  const prefs = chromePrefs();

  onMount(() => {
    void policy.refresh();
  });

  const present = $derived(policy.state.kind === "ok" ? presentSections(policy.state.view) : []);
  const resolved = $derived(resolveSection(present.map((s) => s.id), asked));

  $effect(() => {
    if (policy.state.kind !== "ok") return;
    if (asked === resolved) return;
    void goto(`${base}${sectionPath(resolved)}`, { replaceState: true });
  });

  function showing(id: PolicySectionId): boolean {
    return resolved === ALL_SECTION || resolved === id;
  }

  function expectLabel(expect: "reach" | "blocked" | null): string {
    if (expect === "reach") return t(prefs.lang, "m.expectReach");
    if (expect === "blocked") return t(prefs.lang, "m.expectBlocked");
    return "";
  }


</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.policy")}</title>
</svelte:head>

{#if policy.state.kind === "loading"}
  <p>{t(prefs.lang, "m.readingPolicy")}</p>
{:else if policy.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInPolicy")}</p>
  <p><a href="/auth/login?next=/app/policy">{t(prefs.lang, "m.signIn")}</a></p>
{:else if policy.state.kind === "absent"}
  <p>{t(prefs.lang, "m.noPolicyRepo")}</p>
{:else if policy.state.kind === "error"}
  <p>{t(prefs.lang, "m.policyError", { message: policy.state.message })}</p>
{:else}
  {@const view = policy.state.view}
  <p>
    {t(prefs.lang, "m.policySummary", {
      n: view.rows.length,
      hosts: view.hostIds.length,
      generation: view.generation ?? t(prefs.lang, "m.noGeneration"),
    })}
    {#if view.site}
      · {view.site}
    {/if}
  </p>
  {#if view.freshness?.state === "fresh"}
    <p class="banner ok">{t(prefs.lang, "m.fresh")}</p>
  {:else if view.freshness?.state === "stale"}
    <p class="banner warn">
      {t(prefs.lang, "m.policyStale", {
        rendered: view.freshness.rendered ?? t(prefs.lang, "m.unnamedCheckout"),
        repo: view.freshness.repository.slice(0, 7),
      })}
    </p>
  {:else if view.freshness?.state === "unknown"}
    <p class="banner hatch">{t(prefs.lang, "m.unknownFreshness", { why: view.freshness.why })}</p>
  {/if}
  {#if view.renderer && view.renderer.build !== view.renderer.mine}
    <p class="banner warn">
      {#if view.renderer.build}
        {t(prefs.lang, "m.rendererMismatch", { build: view.renderer.build, mine: view.renderer.mine })}
      {:else}
        {t(prefs.lang, "m.rendererSilent")}
      {/if}
    </p>
  {/if}
  {#if !view.canWrite}
    <p class="dim">{t(prefs.lang, "m.policyReadOnly")}</p>
  {/if}

  <nav class="sections">
    {#each present as section (section.id)}
      <a href="{base}{sectionPath(section.id)}" aria-current={resolved === section.id ? "page" : undefined}>
        {sectionLabel(section.id, prefs.lang)}{#if section.count !== undefined} ({section.count}){/if}
      </a>
    {/each}
    <a href="{base}{sectionPath(ALL_SECTION)}" aria-current={resolved === ALL_SECTION ? "page" : undefined}>
      {t(prefs.lang, "page.showAll")}
    </a>
  </nav>

  {#snippet covCell(cell: CoverageCellView)}
    <div>
      <Chip kind={coverageKind(cell.verdict)} hatch={cell.verdict === "unknown" || cell.stale}>
        {#if cell.verdict === "pass"}✓ {t(prefs.lang, "v.pass")}
        {:else if cell.verdict === "fail"}✕ {t(prefs.lang, "v.fail")}
        {:else if cell.verdict === "n/a"}{t(prefs.lang, "v.na")}
        {:else}? {t(prefs.lang, "v.unknown")}
        {/if}
      </Chip>
      {#if cell.stale}
        <Chip kind="warn" hatch>△ {t(prefs.lang, "v.stale")}</Chip>
      {/if}
      {#if cell.observedFrom || cell.at}
        <div class="dim">{[cell.observedFrom, cell.at].filter(Boolean).join(" · ")}</div>
      {/if}
    </div>
  {/snippet}

  {#if view.edit}
    <PolicyWrite edit={view.edit} showRules={showing("rules")} showFiles={showing("files")} />
  {/if}

  {#if showing("baseline") && view.baseline.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.baseline.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.what")}</th>
            <th>{t(prefs.lang, "c.proto")}</th>
            <th>{t(prefs.lang, "c.ports")}</th>
            <th>{t(prefs.lang, "c.source")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.baseline as row (row.desc + row.proto + row.ports)}
            <tr>
              <td>{row.desc}</td>
              <td>{row.proto}</td>
              <td>{row.ports.trim() === "" ? t(prefs.lang, "v.all") : row.ports}</td>
              <td>{sourceCell(row.srcCidrs, row.anySource, prefs.lang)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("policies")}
    {@const findings = policyFindings(view.rows, prefs.lang)}
    <section>
      <h2>{t(prefs.lang, "s.policies")} · {view.rows.length}</h2>
      <p>{t(prefs.lang, "m.disabledStay")}</p>
      {#if findings.length > 0}
        <div class="chips findings">
          {#each findings as finding (finding.key)}
            <Chip kind={finding.kind} hatch={finding.hatch}>
              {#if finding.mark}{finding.mark} {/if}{finding.label} {finding.count}{#if finding.note} — {finding.note}{/if}
            </Chip>
          {/each}
        </div>
      {/if}
      <div class="scroll">
        <table class="policy-rows">
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.rule")}</th>
              <th>{t(prefs.lang, "c.action")}</th>
              <th>{t(prefs.lang, "c.protoPorts")}</th>
              <th>{t(prefs.lang, "c.pri")}</th>
              <th>{t(prefs.lang, "c.renderedHosts")}</th>
              <th>{t(prefs.lang, "c.skippedOn")}</th>
              <th>{t(prefs.lang, "c.srcCidrs")}</th>
              <th>{t(prefs.lang, "c.findings")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.rows as row (row.id)}
              <tr class={policyRowClass(row)}>
                <td>
                  <span class="name" title={row.name}>{row.name}</span>
                  <div class="dim id" title={row.id}>{row.id}</div>
                  {#if row.notes}
                    <div class="dim notes" title={row.notes}>{row.notes}</div>
                  {/if}
                </td>
                <td>
                  {#if row.action === "deny"}
                    <Chip kind="bad">■ {t(prefs.lang, "v.deny")}{#if row.denyMode} · {denyModeWord(prefs.lang, row.denyMode)}{/if}</Chip>
                  {:else}
                    <Chip kind="ok">□ {t(prefs.lang, "v.allow")}</Chip>
                  {/if}
                </td>
                <td class="mono">{row.proto} {row.ports.trim() === "" ? t(prefs.lang, "m.allPorts") : row.ports}</td>
                <td class="num">{row.priority}</td>
                <td class="mono">{placement(row, prefs.lang)}</td>
                <td class="mono">{row.skippedOn.join(", ") || "—"}</td>
                <td class="mono">{sourceCell(row.srcCidrs, row.risks.includes("any-source"), prefs.lang)}</td>
                <td>
                  {#if row.risks.length === 0}
                    <span class="ok">{t(prefs.lang, "m.none")}</span>
                  {:else}
                    <div class="chips">
                      {#each row.risks as risk (risk)}
                        <Chip kind={riskKind(risk)}>{riskLabel(risk, prefs.lang)}</Chip>
                      {/each}
                    </div>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if showing("zones") && view.zones.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.zones.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.zone")}</th>
            <th>{t(prefs.lang, "c.trust")}</th>
            <th>{t(prefs.lang, "c.ranges")}</th>
            <th>{t(prefs.lang, "c.asSource")}</th>
            <th>{t(prefs.lang, "c.asDest")}</th>
            <th>{t(prefs.lang, "c.admits")}</th>
            <th>{t(prefs.lang, "c.notes")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.zones as row (row.id)}
            <tr>
              <td>{row.name}</td>
              <td>{row.trust}</td>
              <td><code>{row.cidrs.join(", ")}</code></td>
              <td>{row.asSource}</td>
              <td>{row.asDestination}</td>
              <td>{row.admits}</td>
              <td>{row.notes}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("crossings")}
    <section>
      <h2>{t(prefs.lang, "s.crossings.heading")}</h2>
      {#if view.crossings.length === 0}
        <p>{t(prefs.lang, "s.crossings.none")}</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.policy")}</th>
              <th>{t(prefs.lang, "c.from")}</th>
              <th>{t(prefs.lang, "c.to")}</th>
              <th>{t(prefs.lang, "c.gain")}</th>
              <th>{t(prefs.lang, "c.action")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.crossings as row (row.policyId + row.from + row.to)}
              <tr>
                <td><code>{row.policyId}</code> {row.policyName}</td>
                <td>{row.from}</td>
                <td>{row.to}</td>
                <td>{row.gain}</td>
                <td>{actionWord(prefs.lang, row.action)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}

  {#if showing("coverage") && view.coverage}
    <section>
      <h2>{t(prefs.lang, "s.coverage")} · {view.coverage.rows.length}</h2>
      <p>
        {t(prefs.lang, "m.coverageCounts", {
          fail: view.coverage.failing,
          unknown: view.coverage.unknown,
          pass: view.coverage.passing,
        })}
      </p>
      <div class="scroll">
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.check")}</th>
              <th>{t(prefs.lang, "c.v4")}</th>
              <th>{t(prefs.lang, "c.v6")}</th>
              <th>{t(prefs.lang, "c.targets")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.coverage.rows as row (row.title + row.targets.join())}
              <tr>
                <td>
                  <span class="name">{row.title}</span>
                  {#if expectLabel(row.expect)}
                    <div class="dim">{expectLabel(row.expect)}</div>
                  {/if}
                </td>
                <td>{@render covCell(row.v4)}</td>
                <td>{@render covCell(row.v6)}</td>
                <td class="mono">{row.targets.join(", ")}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if showing("devices") && view.devices}
    <section>
      <h2>{t(prefs.lang, "s.devices")} · {view.devices.rows.length}</h2>
      <p>
        {#if view.devices.compared}
          {t(prefs.lang, "m.compared")}{#if view.devices.readAt} · {t(prefs.lang, "m.readAt", { at: view.devices.readAt })}{/if}
        {:else}
          {t(prefs.lang, "m.devicesUncompared")}
        {/if}
        {#if view.devices.addressless > 0}
          · {t(prefs.lang, "m.addressless", { n: view.devices.addressless })}
        {/if}
      </p>
      {#if view.devices.unapproved.length > 0}
        <p class="banner warn">
          {t(prefs.lang, "m.unapproved", {
            n: view.devices.unapproved.length,
            names: view.devices.unapproved.map((d) => d.v4 ? `${d.deviceName} (${d.v4})` : d.deviceName).join(", "),
          })}
        </p>
      {/if}
      <div class="scroll">
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.device")}</th>
              <th>{t(prefs.lang, "c.state")}</th>
              <th>{t(prefs.lang, "c.policyAddr")}</th>
              <th>{t(prefs.lang, "c.observed")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.devices.rows as row (row.deviceName + row.userEmail)}
              <tr>
                <td>
                  <span class="name">{row.deviceName}</span>
                  <div class="dim id">{row.userEmail}{#if row.zone} · {t(prefs.lang, "c.zone")} {row.zone}{/if}</div>
                </td>
                <td>
                  {#if row.state === "ok"}
                    <Chip kind="ok">✓ {t(prefs.lang, "v.ok")}</Chip>
                  {:else if row.state === "moved"}
                    <Chip kind="warn">→ {t(prefs.lang, "m.moved")}</Chip>
                  {:else if row.state === "gone"}
                    <Chip kind="bad">✕ {t(prefs.lang, "m.gone")}</Chip>
                  {:else}
                    <Chip kind="none">◇ {t(prefs.lang, "m.unchecked")}</Chip>
                    <div class="dim">{t(prefs.lang, "m.notMeasured")}</div>
                  {/if}
                </td>
                <td class="mono">{row.v4 || "—"}</td>
                <td class="mono">
                  {#if row.state === "ok"}
                    {t(prefs.lang, "m.matches")}
                  {:else if row.state === "moved" && row.liveV4}
                    {t(prefs.lang, "m.currently", { addr: row.liveV4 })}
                  {:else if row.state === "gone"}
                    {t(prefs.lang, "m.notInRegistry")}
                  {:else}
                    <span class="hatch dim">{t(prefs.lang, "m.noMeasurement")}</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if showing("users") && view.users.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.users.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.user")}</th>
            <th>{t(prefs.lang, "c.devices")}</th>
            <th>{t(prefs.lang, "c.zones")}</th>
            <th>{t(prefs.lang, "c.v4")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.users as row (row.email)}
            <tr>
              <td>{row.email}</td>
              <td>{row.devices}</td>
              <td>{row.zones.join(", ")}</td>
              <td><code>{row.v4.join(", ")}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("workload") && view.workload.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.workload.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.id")}</th>
            <th>{t(prefs.lang, "c.name")}</th>
            <th>{t(prefs.lang, "c.action")}</th>
            <th>{t(prefs.lang, "c.source")}</th>
            <th>{t(prefs.lang, "c.destination")}</th>
            <th>{t(prefs.lang, "c.proto")}</th>
            <th>{t(prefs.lang, "c.ports")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.workload as row (row.id)}
            <tr>
              <td><code>{row.id}</code></td>
              <td>{row.name}</td>
              <td>{actionWord(prefs.lang, row.action)}</td>
              <td>{row.src}</td>
              <td>{row.dst}</td>
              <td>{row.proto}</td>
              <td>{row.ports.trim() === "" ? t(prefs.lang, "v.all") : row.ports}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("hosts") && view.hosts.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.hosts")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.host")}</th>
            <th>{t(prefs.lang, "c.stage")}</th>
            <th>{t(prefs.lang, "c.input")}</th>
            <th>{t(prefs.lang, "c.egress")}</th>
            <th>{t(prefs.lang, "c.skipped")}</th>
            {#if view.hosts.some((h) => h.fleet)}
              <th>{t(prefs.lang, "c.state")}</th>
              <th>{t(prefs.lang, "c.generation")}</th>
              <th>{t(prefs.lang, "c.age")}</th>
            {/if}
          </tr>
        </thead>
        <tbody>
          {#each view.hosts as row (row.id)}
            <tr>
              <td>{row.id}</td>
              <td>{row.stage}</td>
              <td>{row.inputCount}</td>
              <td>{row.egressCount}</td>
              <td>{row.skipped.join(" ") || "—"}</td>
              {#if view.hosts.some((h) => h.fleet)}
                <td>{row.fleet?.state ?? "—"}</td>
                <td>{row.fleet?.generation ?? "—"}</td>
                <td>{row.fleet?.ageSec === undefined || row.fleet.ageSec === null ? "—" : `${row.fleet.ageSec}s`}</td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("membership") && view.membership.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.membership")} · {view.membership.length}</h2>
      <p>{t(prefs.lang, "m.podCountNeedsAt")}</p>
      {#each view.membership as row (`${row.kind}:${row.name}:${row.host}`)}
        <article class="card">
          <p>
            <strong>{row.kind} {row.name}</strong>
            · {t(prefs.lang, "m.members", { n: row.members.length })}
            {#if row.at}
              · {t(prefs.lang, "m.readAt", { at: row.at })}
            {:else}
              · <span class="warn">{t(prefs.lang, "m.noAt")}</span>
            {/if}
          </p>
          <p class="dim">{t(prefs.lang, "c.host")} {row.host} · {t(prefs.lang, "c.usedBy")} {row.usedBy.join(", ") || "—"}</p>
        </article>
      {/each}
    </section>
  {/if}

  {#if showing("objects") && view.objects.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.objects")} · {view.objects.length}</h2>
      {#if view.objects.some((o) => o.usedBy.length === 0)}
        <p class="banner warn">
          {t(prefs.lang, "m.unusedObjects", {
            names: view.objects.filter((o) => o.usedBy.length === 0).map((o) => o.name || o.id).join(", "),
          })}
        </p>
      {/if}
      <div class="scroll">
        <table>
          <thead>
            <tr>
              <th>{t(prefs.lang, "c.object")}</th>
              <th>{t(prefs.lang, "c.members")}</th>
              <th>{t(prefs.lang, "c.usedBy")}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.objects as row (row.id)}
              <tr>
                <td><code>{row.id}</code> {row.name}</td>
                <td class="mono">{row.members.join(", ")}</td>
                <td class="mono">{row.usedBy.join(", ") || t(prefs.lang, "m.unused")}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if showing("services") && view.services.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.services")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.id")}</th>
            <th>{t(prefs.lang, "c.name")}</th>
            <th>{t(prefs.lang, "c.members")}</th>
            <th>{t(prefs.lang, "c.usedBy")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.services as row (row.id)}
            <tr>
              <td><code>{row.id}</code></td>
              <td>{row.name}</td>
              <td>{row.members.join(", ")}</td>
              <td>{row.usedBy.join(" ") || t(prefs.lang, "m.unused")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("feeds") && view.feeds.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.feeds")} · {view.feeds.length}</h2>
      {#if view.feeds.some((f) => f.usedBy.length === 0)}
        <p class="banner warn">
          {t(prefs.lang, "m.unusedFeeds", {
            names: view.feeds.filter((f) => f.usedBy.length === 0).map((f) => f.ref).join(", "),
          })}
        </p>
      {/if}
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.feed")}</th>
            <th>{t(prefs.lang, "c.usedBy")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.feeds as row (row.ref)}
            <tr>
              <td><code>{row.ref}</code></td>
              <td>{row.usedBy.join(" ") || t(prefs.lang, "m.unused")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("address-space") && view.addressSpace.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.addressSpace.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.cidr")}</th>
            <th>{t(prefs.lang, "c.asSource")}</th>
            <th>{t(prefs.lang, "c.asHost")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.addressSpace as row (row.cidr)}
            <tr>
              <td><code>{row.cidr}</code></td>
              <td>{row.asSource}</td>
              <td>{row.asHost.join(", ")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if showing("history") && view.history.length > 0}
    <section>
      <h2>{t(prefs.lang, "s.history.heading")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "c.commit")}</th>
            <th>{t(prefs.lang, "c.subject")}</th>
            <th>{t(prefs.lang, "c.author")}</th>
            <th>{t(prefs.lang, "c.status")}</th>
            <th>{t(prefs.lang, "c.liveOn")}</th>
          </tr>
        </thead>
        <tbody>
          {#each view.history as row (row.id)}
            <tr>
              <td><code>{row.id}</code></td>
              <td>{row.subject}</td>
              <td>{row.author}</td>
              <td>{row.status}</td>
              <td>{row.liveOn.join(", ")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
{/if}

<style>
  .id { font-family: var(--font-mono); font-size: 10px; }
  tr.hit-bad { background: var(--danger-bg); }
  tr.hit-warn { background: var(--warn-bg); }
  .findings { margin: 0 0 12px; }
</style>

