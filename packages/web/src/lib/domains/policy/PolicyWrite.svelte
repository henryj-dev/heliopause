<script lang="ts">
  import { untrack } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { whoQuery } from "$lib/shell/who.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import RuleTable from "./RuleTable.svelte";
  import type { PolicyEdit } from "./screen";
  import { readPolicyDoc, rulesWithoutNotes, writePolicyDoc, type PolicyDoc } from "./rules";
  import {
    editBody,
    mergeBody,
    proposeBlock,
    proposePolicyBody,
    proposeRefusal,
    readEditReply,
    readMergeReply,
    readPrReply,
    readProposeReply,
    writeFailMessage,
    writeHeaders,
    type PrStatus,
  } from "./write";

  const prefs = chromePrefs();
  const who = whoQuery();
  const write = writeAsk();

  let { edit, showRules, showFiles }: {
    edit: PolicyEdit;
    showRules: boolean;
    showFiles: boolean;
  } = $props();

  // Seeded once. A later refresh of `edit` must not wipe a draft the operator
  // is still looking at — dirty is against these copies, not against the prop.
  const initialContent = untrack(() => edit.content);
  const initialFiles = untrack(() => Object.fromEntries(edit.more.map((f) => [f.path, f.content])));
  const initialRead = readPolicyDoc(initialContent);
  let doc = $state<PolicyDoc | null>(initialRead.ok ? initialRead.doc : null);
  let parseError = initialRead.ok ? "" : initialRead.reason;
  let fallback = $state(initialRead.ok ? "" : initialContent);
  let tableDirty = $state(false);
  let files = $state<Record<string, string>>(initialFiles);
  let servedFiles = $state<Record<string, string>>({ ...initialFiles });
  let branch = $state("");
  let lastCommit = $state("");
  let prUrl = $state("");
  let prNumber = $state<number | null>(null);
  let prTitle = $state("");
  let note = $state("");
  let noteKind = $state<"ok" | "bad">("ok");
  let busy = $state("");
  let pr = $state<PrStatus | null>(null);
  /**
   * The pull request to look at, as a string because it is bound to a text input.
   *
   * Typed as well as remembered, because a page reload loses `prNumber` and the review it was
   * waiting on outlives the tab. Without this box the only way back to a pull request opened
   * yesterday is the site the console exists to stop sending people to.
   */
  let prLookup = $state("");

  const dirtyPaths = $derived.by(() => {
    const paths: string[] = [];
    if (doc ? tableDirty : fallback !== initialContent) paths.push(edit.path);
    for (const file of edit.more) {
      if ((files[file.path] ?? "") !== (servedFiles[file.path] ?? file.content)) paths.push(file.path);
    }
    return paths;
  });

  function csrf(): string | null {
    return who.state.kind === "ok" ? who.state.view.csrf : null;
  }

  function say(message: string, bad = false): void {
    noteKind = bad ? "bad" : "ok";
    note = message;
  }

  function mark(): void {
    tableDirty = true;
  }

  async function save(path: string, content: string, after?: () => void): Promise<void> {
    if (!content) {
      say(t(prefs.lang, "file.empty"), true);
      return;
    }
    busy = path;
    try {
      const res = await fetch("/api/policy/edit", {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf()),
        body: editBody(path, content, branch),
      });
      const body: unknown = await res.json();
      const reply = readEditReply(body);
      if (!res.ok || !reply.ok) {
        throw new Error(reply.ok ? `HTTP ${res.status}` : writeFailMessage(reply, (key) => t(prefs.lang, key)));
      }
      branch = reply.branch;
      lastCommit = reply.commit;
      prUrl = "";
      prNumber = null;
      after?.();
      let message = t(prefs.lang, "rule.saved", { commit: reply.commit.slice(0, 8), branch: reply.branch });
      let bad = false;
      if (path === edit.path && doc) {
        const bare = rulesWithoutNotes(doc);
        if (bare.length) {
          message += t(prefs.lang, "m.noReason", { ids: bare.join(", ") });
          bad = true;
        }
      }
      say(message, bad);
    } catch (e) {
      say(e instanceof Error ? e.message : String(e), true);
    } finally {
      busy = "";
    }
  }

  function saveRules(): void {
    if (doc) {
      void save(edit.path, writePolicyDoc(doc), () => {
        tableDirty = false;
      });
      return;
    }
    void save(edit.path, fallback);
  }

  function saveFile(path: string): void {
    void save(path, files[path] ?? "", () => {
      servedFiles = { ...servedFiles, [path]: files[path] ?? "" };
    });
  }

  async function propose(): Promise<void> {
    const block = proposeBlock(branch, dirtyPaths);
    if (!block.ok) {
      const refusal = proposeRefusal(block);
      say(t(prefs.lang, refusal.key, refusal.paths ? { paths: refusal.paths } : {}), true);
      return;
    }
    busy = "propose";
    try {
      const res = await fetch("/api/policy/propose", {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf()),
        body: proposePolicyBody(branch, prTitle),
      });
      const body: unknown = await res.json();
      const reply = readProposeReply(body);
      if (!res.ok || !reply.ok) {
        throw new Error(reply.ok ? `HTTP ${res.status}` : writeFailMessage(reply, (key) => t(prefs.lang, key)));
      }
      prUrl = reply.url;
      prNumber = reply.number;
      prLookup = String(reply.number);
      say(t(prefs.lang, "rule.proposed", { number: reply.number, url: reply.url }));
      // Asked for straight away, so the operator sees "checks still running" rather than a button
      // whose state they have to guess at. It is the same sentence the route would answer with.
      void loadPr(reply.number);
    } catch (e) {
      say(e instanceof Error ? e.message : String(e), true);
    } finally {
      busy = "";
    }
  }

  /**
   * What the manager says about the pull request, including whether this operator may merge it.
   *
   * The verdict is never computed here. `mergeRefusal` in the manager decides it for both the button
   * and the route, so a browser that drew its own conclusion would be a second copy of the rule —
   * and the copy is the one that goes stale, leaving a live button over a route that refuses.
   */
  async function loadPr(number: number): Promise<void> {
    if (!Number.isSafeInteger(number) || number < 1) return;
    busy = "pr";
    try {
      const res = await fetch(`/api/policy/pr?number=${number}`, { credentials: "same-origin" });
      const reply = readPrReply(await res.json());
      if (!reply.ok) {
        pr = null;
        throw new Error(writeFailMessage(reply, (key) => t(prefs.lang, key)));
      }
      pr = reply.status;
      prNumber = reply.status.number;
      if (reply.status.url) prUrl = reply.status.url;
    } catch (e) {
      say(e instanceof Error ? e.message : String(e), true);
    } finally {
      busy = "";
    }
  }

  async function merge(): Promise<void> {
    if (!pr) return;
    // The warning and the code are asked for here, before the request, because the manager will
    // demand the code and a 401 after the fact tells the operator nothing about *why* this merge
    // was different from the last one. `solo` comes from the manager — see `PrStatus.solo`.
    const answer = await write.ask({
      what: t(prefs.lang, "rule.soloMerge"),
      warning: pr.solo ? t(prefs.lang, "rule.soloWarn", { number: pr.number }) : undefined,
      needsOtp: pr.solo,
    });
    if (answer === null) return;
    busy = "merge";
    try {
      const res = await fetch("/api/policy/merge", {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(csrf()),
        body: mergeBody(pr.number, answer.otp),
      });
      const reply = readMergeReply(await res.json());
      if (!reply.ok) throw new Error(writeFailMessage(reply, (key) => t(prefs.lang, key)));
      say(t(prefs.lang, reply.solo ? "rule.mergedSolo" : "rule.merged", {
        number: reply.number,
        sha: reply.sha.slice(0, 8),
      }));
      await loadPr(reply.number);
    } catch (e) {
      say(e instanceof Error ? e.message : String(e), true);
    } finally {
      busy = "";
    }
  }
</script>

{#if showRules}
  <section>
    <h2>
      {t(prefs.lang, "s.rules")} · <code>{edit.path}</code>
      {#if dirtyPaths.length > 0}
        <span class="chip warn">{t(prefs.lang, "m.dirtyPlaces", { n: dirtyPaths.length })}</span>
      {/if}
    </h2>
    <p>{t(prefs.lang, "m.rulesAreSource")} <a href="{base}/policy/policies">{t(prefs.lang, "s.policies")}</a></p>
    {#if dirtyPaths.length > 0}
      <p class="banner warn">{t(prefs.lang, "m.leaveLoses")}</p>
    {/if}
    {#if doc}
      <RuleTable {doc} {mark} />
    {:else}
      <p class="bad">{t(prefs.lang, "m.notATable", { reason: parseError })}</p>
      <textarea bind:value={fallback} rows="18" spellcheck="false" aria-label={edit.path}></textarea>
    {/if}
  </section>
{/if}

{#if showFiles && edit.more.length > 0}
  <section>
    <h2>{t(prefs.lang, "s.files")}</h2>
    <p>{t(prefs.lang, "m.filesSameBranch")}</p>
    {#each edit.more as file (file.path)}
      <h3>
        <code>{file.path}</code>
        {#if dirtyPaths.includes(file.path)}
          <span class="dim"> · {t(prefs.lang, "file.dirty")}</span>
        {/if}
      </h3>
      <textarea
        value={files[file.path] ?? file.content}
        rows="14"
        spellcheck="false"
        aria-label={file.path}
        oninput={(e) => {
          files = { ...files, [file.path]: e.currentTarget.value };
        }}
      ></textarea>
      <p class="act">
        <button type="button" disabled={busy !== ""} onclick={() => saveFile(file.path)}>
          {t(prefs.lang, "m.savePath", { path: file.path })}
        </button>
      </p>
    {/each}
  </section>
{/if}

{#if showRules || (showFiles && edit.more.length > 0)}
  <section>
    <p class="act">
      <input bind:value={branch} placeholder={t(prefs.lang, "m.branch")} aria-label={t(prefs.lang, "m.branch")} spellcheck="false">
      {#if showRules}
        <button type="button" disabled={busy !== ""} onclick={() => saveRules()}>{t(prefs.lang, "rule.save")}</button>
        <span class="dim">{t(prefs.lang, "m.noMergeNoPublish")}</span>
      {/if}
    </p>
    {#if lastCommit}
      <p class="banner ok">
        {t(prefs.lang, "m.committedBanner", { branch, commit: lastCommit.slice(0, 7) })}
      </p>
    {/if}
    <p class="act">
      <input bind:value={prTitle} placeholder={t(prefs.lang, "m.prTitle")} aria-label={t(prefs.lang, "m.prTitle")} class="wide">
      <button type="button" disabled={busy !== ""} onclick={() => void propose()}>{t(prefs.lang, "rule.propose")}</button>
    </p>
    {#if prNumber !== null}
      <p class="banner info">
        {t(prefs.lang, "m.prOpened", { number: prNumber })}
        {#if prUrl}
          · <a href={prUrl}>{prUrl}</a>
        {/if}
      </p>
    {/if}

    <!--
      The step that used to leave the console. Merging adopts the source and moves nothing on the
      fleet — the note after a merge says so, because "merged" on a policy screen reads like a deploy.
    -->
    <p class="act">
      <input
        bind:value={prLookup}
        placeholder="#"
        aria-label={t(prefs.lang, "rule.prNumber")}
        class="pr"
        inputmode="numeric"
      >
      <button type="button" disabled={busy !== ""} onclick={() => void loadPr(Number(prLookup))}>
        {t(prefs.lang, "rule.refresh")}
      </button>
      {#if pr}
        <button type="button" disabled={busy !== "" || !pr.mayMerge} onclick={() => void merge()}>
          {busy === "merge" ? t(prefs.lang, "rule.merging") : t(prefs.lang, "rule.merge")}
        </button>
      {/if}
    </p>

    {#if pr}
      <p class="dim">
        {#if pr.proposedBy}{t(prefs.lang, "rule.proposedBy", { who: pr.proposedBy })} · {/if}
        {t(prefs.lang, "rule.checksOn", { sha: pr.headSha.slice(0, 8) })}
      </p>
      <ul class="checks">
        {#each pr.checks as check (check.name)}
          <li class={check.state}>
            <code>{check.name}</code>
            <span class="dim"> · {check.detail || check.state}</span>
          </li>
        {/each}
      </ul>
      {#if !pr.mayMerge && pr.why}
        <p class="banner warn">{t(prefs.lang, "rule.mergeGate", { why: pr.why })}</p>
      {:else if pr.solo}
        <p class="banner warn">{t(prefs.lang, "rule.soloWarn", { number: pr.number })}</p>
      {/if}
    {/if}
  </section>
{/if}

{#if write.pending}
  <WriteDialog spec={write.pending.spec} onsubmit={write.submit} oncancel={write.cancel} />
{/if}

{#if note}
  <div class="note-slot {noteKind}">{note}</div>
{/if}

<style>
  .pr { width: 6rem; }
  .checks { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
  .checks li.failure code { color: var(--danger-fg); }
  .checks li.pending code { color: var(--text-2); }

  textarea {
    width: 100%;
    min-height: 16rem;
    resize: vertical;
  }
  .wide { flex: 1; min-width: 12rem; }
  h2 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
</style>
