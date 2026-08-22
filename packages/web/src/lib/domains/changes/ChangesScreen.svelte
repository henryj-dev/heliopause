<script lang="ts">
  import { onMount, tick } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { ageLabel } from "$lib/age";
  import { chromeFreshness } from "$lib/shell/freshness.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import type { WriteSpec } from "$lib/shell/write-ask";
  import { shouldAskOtp } from "$lib/shell/who";
  import { whoQuery } from "$lib/shell/who.svelte";
  import { canOfferApprove, canOfferPublish, planStage, type PlanRow } from "./plans";
  import {
    clockLabel, expireRatio, expireTone, hostRuleTotal, planDomId, planPath, remainingSec, shortPlanHash,
  } from "./present";
  import { PLANS_POLL_MS, plansQuery } from "./query.svelte";
  import { approveBody, proposeBody, publishBody, writeHeaders } from "./write";
  import type { DiffFile } from "./diff";

  let { asked = "" }: { asked?: string } = $props();

  const plans = plansQuery();
  const prefs = chromePrefs();
  const fresh = chromeFreshness();
  const who = whoQuery();
  const write = writeAsk();
  let note = $state("");
  let noteKind = $state<"ok" | "bad">("ok");
  let busy = $state("");
  let target = $state("");
  let openRuleset = $state("");

  const ageSec = $derived(
    plans.state.kind === "ok" ? Math.max(0, Math.floor((fresh.now - plans.state.lastOkAt) / 1000)) : 0,
  );
  const age = $derived(ageLabel(ageSec));

  $effect(() => {
    if (plans.state.kind !== "ok") {
      fresh.publish(null);
      return;
    }
    fresh.publish({
      lastOkAt: plans.state.lastOkAt,
      intervalMs: PLANS_POLL_MS,
      failCount: plans.state.failCount,
    });
    return () => fresh.publish(null);
  });

  onMount(() => {
    void plans.refresh();
    const id = setInterval(() => void plans.refresh(), PLANS_POLL_MS);
    return () => {
      clearInterval(id);
      write.cancel();
    };
  });

  $effect(() => {
    if (plans.state.kind !== "ok") return;
    if (!target && plans.state.view.targets[0]) target = plans.state.view.targets[0];
  });

  $effect(() => {
    if (!asked || plans.state.kind !== "ok") return;
    const id = planDomId(asked);
    void tick().then(() => document.getElementById(id)?.scrollIntoView({ block: "start" }));
  });

  function csrf(): string | null {
    return plans.state.kind === "ok" ? plans.state.view.csrf : null;
  }

  function askWrite(spec: Omit<WriteSpec, "needsOtp">) {
    const view = who.state.kind === "ok" ? who.state.view : null;
    return write.ask({ ...spec, needsOtp: shouldAskOtp(view) });
  }

  async function act(kind: "approve" | "publish", plan: PlanRow): Promise<void> {
    const answer = await askWrite({
      what: t(prefs.lang, kind === "approve" ? "m.otpApprove" : "m.otpPublish"),
      warning: kind === "publish"
        ? t(prefs.lang, "m.publishConfirm", { hash: plan.hash.slice(0, 20) })
        : undefined,
    });
    if (answer === null) return;
    busy = `${kind}:${plan.hash}`;
    try {
      const res = await fetch(`/api/${kind}`, {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf()),
        body: kind === "approve" ? approveBody(plan.hash, answer.otp) : publishBody(plan.hash, answer.otp),
      });
      const body = await res.json() as { error?: string; approval?: { by: string }; generation?: string; target?: string; serving?: string };
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      noteKind = "ok";
      note = kind === "approve"
        ? t(prefs.lang, "m.approveNote", { who: body.approval?.by ?? "?" })
        : t(prefs.lang, "m.publishNote", {
          generation: body.generation ?? "?",
          target: body.target ?? "?",
          serving: body.serving ?? "?",
        });
      await plans.refresh();
      void who.refresh();
    } catch (e) {
      noteKind = "bad";
      note = (e as Error).message;
    } finally {
      busy = "";
    }
  }

  async function propose(): Promise<void> {
    if (!target) return;
    busy = "propose";
    try {
      const res = await fetch("/api/policy/plan", {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf()),
        body: proposeBody(target),
      });
      const body = await res.json() as { error?: string; hash?: string };
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      noteKind = "ok";
      note = t(prefs.lang, "m.proposedNote", { hash: body.hash ?? "" });
      await plans.refresh();
      void who.refresh();
    } catch (e) {
      noteKind = "bad";
      note = (e as Error).message;
    } finally {
      busy = "";
    }
  }

  async function copyHash(hash: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(hash);
      noteKind = "ok";
      note = t(prefs.lang, "m.hashCopied");
    } catch (e) {
      noteKind = "bad";
      note = (e as Error).message;
    }
  }

  async function readRuleset(plan: PlanRow, host: string): Promise<void> {
    const key = `${plan.hash}:${host}`;
    if (openRuleset.startsWith(key + "\n")) {
      openRuleset = "";
      return;
    }
    busy = `read:${key}`;
    try {
      const res = await fetch(
        `/api/plans/${encodeURIComponent(plan.hash)}/ruleset?host=${encodeURIComponent(host)}`,
        { credentials: "same-origin" },
      );
      const body = await res.json() as { error?: string; host?: string; stage?: string; rulesetHash?: string; ruleset?: string };
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      openRuleset = `${key}\n${body.host} · ${body.stage} · ${body.rulesetHash}\n\n${body.ruleset ?? ""}`;
    } catch (e) {
      noteKind = "bad";
      note = (e as Error).message;
    } finally {
      busy = "";
    }
  }

  function patchClass(line: string): string {
    if (line.startsWith("+") && !line.startsWith("+++")) return "diff-add";
    if (line.startsWith("-") && !line.startsWith("---")) return "diff-del";
    if (line.startsWith("@@")) return "diff-hunk";
    return "diff-hunk";
  }

  function generatedTotals(files: readonly DiffFile[]): { add: number; del: number } {
    return {
      add: files.reduce((n, file) => n + file.additions, 0),
      del: files.reduce((n, file) => n + file.deletions, 0),
    };
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.changes")}</title>
</svelte:head>

{#if plans.state.kind === "loading"}
  <p>{t(prefs.lang, "m.readingPlans")}</p>
{:else if plans.state.kind === "unauth"}
  <p>{t(prefs.lang, "m.signInPlans")}</p>
  <p><a href="/auth/login?next=/app/changes">{t(prefs.lang, "m.signIn")}</a></p>
{:else if plans.state.kind === "error"}
  <p>{t(prefs.lang, "m.plansError", { message: plans.state.message })}</p>
{:else}
  {@const view = plans.state.view}
  {@const stale = plans.state.failCount > 0}
  {@const pending = view.plans.filter((plan) => planStage(plan) !== "published").length}

  {#if asked && view.plans.every((plan) => plan.hash !== asked)}
    <div class="banner warn">
      <div class="lead">{t(prefs.lang, "m.planMissing", { hash: shortPlanHash(asked) })}</div>
    </div>
  {/if}

  {#if stale}
    <div class="banner warn hatch">
      <div class="lead">{t(prefs.lang, "m.staleBanner", { age })}</div>
      <div>
        {t(prefs.lang, "m.staleFails", { n: plans.state.failCount, error: plans.state.lastFail ?? "" })}
      </div>
      <p class="act">
        <button type="button" onclick={() => void plans.refresh()}>{t(prefs.lang, "m.reread")}</button>
      </p>
    </div>
  {/if}

  {#if view.canWrite && view.targets.length > 0}
    <div class="act" style="padding:9px 11px;background:var(--surface-card);border:1px solid var(--bd-1);border-radius:var(--r-md)">
      <span class="dim" style="font-family:var(--font-mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase">{t(prefs.lang, "m.newPlan")}</span>
      <select bind:value={target}>
        {#each view.targets as name (name)}
          <option value={name}>{name}</option>
        {/each}
      </select>
      <button type="button" disabled={busy !== ""} onclick={() => void propose()}>
        {t(prefs.lang, "m.proposeMerged")}
      </button>
      <span style="flex:1"></span>
      <span class="dim">{t(prefs.lang, "m.publishableFor", { n: view.limits.ttlSec })}</span>
      {#if view.limits.maxPending !== null}
        <span class="dim">{t(prefs.lang, "m.pendingCap", { n: pending, max: view.limits.maxPending })}</span>
      {/if}
      {#if !view.maySoloApprove}
        <span class="dim">{t(prefs.lang, "m.twoPersonMust")}</span>
      {/if}
    </div>
  {:else if !view.maySoloApprove && view.plans.length > 0}
    <p class="lede">{t(prefs.lang, "m.twoPerson")}</p>
  {/if}

  {#if view.plans.length === 0}
    <div class="empty-card">
      <div class="lead">{t(prefs.lang, "m.emptyPlans")}</div>
      <p class="dim">{t(prefs.lang, "m.emptyPlansExplain", { n: view.limits.ttlSec })}</p>
    </div>
  {:else}
    <div class:stale-hold={stale} style="display:flex;flex-direction:column;gap:16px">
    {#each view.plans as plan (plan.hash)}
      {@const stage = planStage(plan)}
      {@const left = remainingSec(plan.proposedAt, view.limits.ttlSec, fresh.now)}
      {@const tone = expireTone(left)}
      {@const diff = plans.diffs[plan.hash]}
      <article class="plan-card {stage}" class:asked={asked === plan.hash} id={planDomId(plan.hash)}>
        <div class="hd">
          <div>
            <p>
              {#if stage === "awaiting"}
                <span class="chip warn">{t(prefs.lang, "m.stageAwaiting")}</span>
              {:else if stage === "approved"}
                <span class="chip info">{t(prefs.lang, "m.stageApproved")}</span>
              {:else}
                <span class="chip mute">{t(prefs.lang, "m.stagePublished")}</span>
              {/if}
              {#if plan.target}
                <span class="chip mute">{plan.target}</span>
              {:else}
                <span class="chip hatch" title={t(prefs.lang, "m.planTargetUnreadNote")}>{t(prefs.lang, "m.planTargetUnread")}</span>
              {/if}
              <code title={plan.hash}>{shortPlanHash(plan.hash)}</code>
              <button type="button" onclick={() => void copyHash(plan.hash)}>{t(prefs.lang, "m.copy")}</button>
              <a href="{base}{planPath(plan.hash)}">{t(prefs.lang, "m.planLink")}</a>
            </p>
            <p class="dim">
              {t(prefs.lang, "m.planMeta", {
                generation: plan.generation,
                hosts: plan.summary.hosts.length,
                rules: hostRuleTotal(plan),
              })}
            </p>
            <p>
              {t(prefs.lang, "m.proposedBy", { generation: plan.generation, who: plan.proposedBy, at: plan.proposedAt })}
              {#if plan.approval}
                · {t(prefs.lang, "m.approvedBy", { who: plan.approval.by })}
              {/if}
            </p>
          </div>
          {#if stage !== "published"}
            <div class="expire {tone}">
              <div class="k">{tone === "bad" ? t(prefs.lang, "m.expiresSoon") : t(prefs.lang, "m.expiresIn")}</div>
              <div>
                <span class="clock">{clockLabel(left)}</span>
                <span class="dim">
                  {tone === "bad" ? t(prefs.lang, "m.expiresKeepApproval") : ""}
                </span>
              </div>
              <div class="expire-bar"><i style="width:{Math.round(expireRatio(left, view.limits.ttlSec) * 100)}%"></i></div>
            </div>
          {/if}
          <div style="flex:1"></div>
          <div class="acts">
            {#if canOfferApprove(plan, view.you, view.canWrite, view.maySoloApprove)}
              <button type="button" disabled={busy !== ""} onclick={() => void act("approve", plan)}>
                {plan.proposedBy === view.you ? t(prefs.lang, "m.approveSolo") : t(prefs.lang, "m.approve")}
              </button>
            {:else if !view.canWrite}
              <p class="dim">{t(prefs.lang, "m.readOnly")}</p>
            {:else if !plan.approval && plan.proposedBy === view.you}
              <p class="dim">{t(prefs.lang, "m.youProposed")}</p>
            {/if}
            {#if canOfferPublish(plan, view.canWrite)}
              <button type="button" data-act="publish" disabled={busy !== ""} onclick={() => void act("publish", plan)}>
                {t(prefs.lang, "m.publishFleet")}
              </button>
            {/if}
            {#if plan.publishedAt}
              <p class="dim">{t(prefs.lang, "m.publishedAt", { at: plan.publishedAt })}</p>
            {/if}
          </div>
        </div>
        {#if plan.approval?.solo && stage === "published"}
          <div class="banner bad" style="margin:11px 13px">
            <div class="lead">{t(prefs.lang, "m.soloBanner")}</div>
            <div>{t(prefs.lang, "m.soloExplain")}</div>
          </div>
        {/if}
        <div class="scroll">
          <table>
            <thead>
              <tr>
                <th>{t(prefs.lang, "c.host")}</th>
                <th>{t(prefs.lang, "c.stage")}</th>
                <th>{t(prefs.lang, "c.rules")}</th>
                <th>{t(prefs.lang, "c.ruleset")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each plan.summary.hosts as host (host.host)}
                <tr>
                  <td><span class="name">{host.host}</span></td>
                  <td>{host.stage}</td>
                  <td class="num">{host.ruleCount}</td>
                  <td><code>{host.rulesetHash.slice(0, 12)}</code></td>
                  <td>
                    <button type="button" disabled={busy !== ""} onclick={() => void readRuleset(plan, host.host)}>
                      {t(prefs.lang, "m.expandRuleset")}
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if openRuleset.startsWith(`${plan.hash}:`)}
          <pre>{openRuleset.slice(openRuleset.indexOf("\n") + 1)}</pre>
        {/if}
        {#if stage !== "published"}
          <div class="diff-box">
            {#if !diff}
              <span class="dim">{t(prefs.lang, "m.lookingUp")}</span>
            {:else if diff.kind === "same"}
              <span class="chip ok">{t(prefs.lang, "m.diffSame", { base: diff.base, head: diff.head })}</span>
            {:else if diff.kind === "unavailable"}
              <div class="banner hatch">
                <div class="lead">{t(prefs.lang, "m.diffUnavailable")}</div>
                <div>{diff.reason}</div>
                <p class="dim">{t(prefs.lang, "m.diffUnavailableNote")}</p>
              </div>
            {:else if diff.kind === "error"}
              <p class="dim">{t(prefs.lang, "m.diffError", { message: diff.reason })}</p>
            {:else}
              {@const gen = generatedTotals(diff.generated)}
              <div>
                <span class="dim" style="letter-spacing:.1em;text-transform:uppercase">{t(prefs.lang, "m.diffHeading")}</span>
                <span class="dim">
                  {t(prefs.lang, "m.diffRange", { base: diff.base, head: diff.head, n: diff.commits.length })}
                </span>
              </div>
              {#each diff.commits as commit (commit.sha + commit.message)}
                <div class="dim"><code>{commit.sha}</code> {commit.message} · {commit.author}</div>
              {/each}
              {#each diff.files as file (file.filename)}
                <div>
                  <div>
                    <strong>{file.filename}</strong>
                    <span class="ok">+{file.additions}</span>
                    <span class="bad">−{file.deletions}</span>
                    <span class="chip mute">{t(prefs.lang, "m.authoredFile")}</span>
                  </div>
                  {#if file.patch}
                    <pre class="diff-patch">{#each file.patch.split("\n") as line, i (`${i}:${line}`)}<span class={patchClass(line)}>{line}{"\n"}</span>{/each}</pre>
                  {/if}
                </div>
              {/each}
              {#if diff.generated.length > 0}
                <details>
                  <summary>{t(prefs.lang, "m.generatedFiles", { n: diff.generated.length, add: gen.add, del: gen.del })}</summary>
                  {#each diff.generated as file (file.filename)}
                    <div class="dim">{file.filename} · {file.status} · +{file.additions} −{file.deletions}</div>
                  {/each}
                </details>
              {/if}
            {/if}
          </div>
        {/if}
      </article>
    {/each}
    </div>
  {/if}
{/if}

{#if note}
  <div class="note-slot {noteKind}">{note}</div>
{/if}

{#if write.pending}
  <WriteDialog spec={write.pending.spec} onsubmit={write.submit} oncancel={write.cancel} />
{/if}

<style>
  .stale-hold { opacity: 0.72; }
</style>
