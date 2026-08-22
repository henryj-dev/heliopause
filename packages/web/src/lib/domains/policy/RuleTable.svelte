<script lang="ts">
  import { onMount } from "svelte";
  import { denyModeWord, t, type MessageKey } from "$lib/i18n";
  import Chip from "$lib/shell/Chip.svelte";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import "./rows.css";
  import RuleEditModal from "./RuleEditModal.svelte";
  import {
    addRule,
    applyDraft,
    deleteRule,
    draftFromRule,
    groupLabel,
    newRule,
    portsText,
    RULE_COLUMNS,
    type PolicyDoc,
    type Rule,
    type RuleDraft,
  } from "./rules";

  const prefs = chromePrefs();
  const write = writeAsk();

  let { doc, mark }: { doc: PolicyDoc; mark: () => void } = $props();

  const groups = $derived(Object.keys(doc.groups));

  type Editor =
    | { kind: "edit"; group: string; rule: Rule; draft: RuleDraft }
    | { kind: "create"; draft: RuleDraft };

  let editor = $state<Editor | null>(null);

  function openEdit(group: string, rule: Rule): void {
    editor = { kind: "edit", group, rule, draft: draftFromRule(group, rule) };
  }

  function openCreate(): void {
    const group = groups[0] ?? "";
    editor = { kind: "create", draft: draftFromRule(group, newRule()) };
  }

  function apply(): void {
    if (!editor) return;
    if (editor.kind === "create") {
      const rule = addRule(doc, editor.draft.group);
      if (!rule) return;
      applyDraft(doc, editor.draft.group, rule, editor.draft);
    } else {
      applyDraft(doc, editor.group, editor.rule, editor.draft);
    }
    mark();
    editor = null;
  }

  onMount(() => () => write.cancel());

  async function remove(group: string, rule: Rule): Promise<void> {
    const action = t(prefs.lang, rule.action === "allow" ? "v.allow" : "v.deny");
    const answer = await write.ask({
      what: t(prefs.lang, "m.delete"),
      warning: t(prefs.lang, "m.deleteConfirm", { id: rule.id, action }),
      needsOtp: false,
    });
    if (answer === null) return;
    if (!deleteRule(doc, group, rule)) return;
    mark();
  }
</script>

<div class="scroll">
  <table class="policy-rows">
    <thead>
      <tr>
        {#each RULE_COLUMNS as heading (heading || "actions")}
          <th>{heading ? t(prefs.lang, heading as MessageKey) : ""}</th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each groups as group (group)}
        {#each doc.groups[group] ?? [] as rule (rule)}
          <tr class:off={!rule.enabled}>
            <td>
              <span class="name" title={rule.name || "—"}>{rule.name || "—"}</span>
              <div class="dim id" title={rule.id}>{rule.id}</div>
              {#if rule.notes}
                <div class="dim notes" title={rule.notes}>{rule.notes}</div>
              {/if}
            </td>
            <td>
              {#if rule.action === "deny"}
                <Chip kind="bad">■ {t(prefs.lang, "v.deny")}{#if rule.denyMode} · {denyModeWord(prefs.lang, rule.denyMode)}{/if}</Chip>
              {:else}
                <Chip kind="ok">□ {t(prefs.lang, "v.allow")}</Chip>
              {/if}
            </td>
            <td class="mono">{portsText(rule.proto, rule.ports)}</td>
            <td class="num">{rule.priority}</td>
            <td class="mono">{groupLabel(group)}</td>
            <td class="acts">
              <button type="button" onclick={() => openEdit(group, rule)}>{t(prefs.lang, "m.edit")}</button>
              <button type="button" onclick={() => void remove(group, rule)}>{t(prefs.lang, "m.delete")}</button>
            </td>
          </tr>
        {/each}
      {/each}
    </tbody>
  </table>
</div>
<p class="act">
  <button type="button" onclick={openCreate}>{t(prefs.lang, "m.addRule")}</button>
</p>

{#if editor}
  <RuleEditModal
    draft={editor.draft}
    {groups}
    title={editor.kind === "create" ? t(prefs.lang, "m.addRule") : t(prefs.lang, "m.editRule", { id: editor.draft.id })}
    onapply={apply}
    oncancel={() => (editor = null)}
  />
{/if}

{#if write.pending}
  <WriteDialog spec={write.pending.spec} onsubmit={write.submit} oncancel={write.cancel} />
{/if}

<style>
  .id { font-family: var(--font-mono); font-size: 10px; }
  .notes { margin-top: 2px; }
  tr.off .name { color: var(--text-2); }
  .acts button { height: var(--ctl-h); }
</style>
