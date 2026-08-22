<script lang="ts">
  import { untrack } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { whoQuery } from "$lib/shell/who.svelte";
  import RuleTable from "./RuleTable.svelte";
  import type { PolicyEdit } from "./screen";
  import { readPolicyDoc, rulesWithoutNotes, writePolicyDoc, type PolicyDoc } from "./rules";
  import {
    editBody,
    proposeBlock,
    proposePolicyBody,
    proposeRefusal,
    readEditReply,
    readProposeReply,
    writeFailMessage,
    writeHeaders,
  } from "./write";

  const prefs = chromePrefs();
  const who = whoQuery();

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
      say(t(prefs.lang, "rule.proposed", { number: reply.number, url: reply.url }));
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
  </section>
{/if}

{#if note}
  <div class="note-slot {noteKind}">{note}</div>
{/if}

<style>
  textarea {
    width: 100%;
    min-height: 16rem;
    resize: vertical;
  }
  .wide { flex: 1; min-width: 12rem; }
  h2 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
</style>
