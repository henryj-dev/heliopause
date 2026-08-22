<script lang="ts">
  import { onMount } from "svelte";
  import { denyModeWord, endpointKind, protoWord, t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import {
    ACTIONS,
    DENY_MODES,
    ENDPOINT_KINDS,
    groupLabel,
    PROTOS,
    type RuleDraft,
  } from "./rules";

  const prefs = chromePrefs();

  let {
    draft,
    groups,
    title,
    onapply,
    oncancel,
  }: {
    draft: RuleDraft;
    groups: string[];
    title: string;
    onapply: () => void;
    oncancel: () => void;
  } = $props();

  let dialog: HTMLDialogElement | undefined = $state();

  onMount(() => {
    dialog?.showModal();
    return () => dialog?.close();
  });
</script>

<dialog
  bind:this={dialog}
  class="modal"
  oncancel={(e) => {
    e.preventDefault();
    oncancel();
  }}
>
  <form
    method="dialog"
    onsubmit={(e) => {
      e.preventDefault();
      onapply();
    }}
  >
    <header class="modal-hd">
      <h3>{title}</h3>
      <p class="sub">{t(prefs.lang, "m.modalSub")}</p>
    </header>
    <div class="modal-body">
      <label>{t(prefs.lang, "c.group")}
        <select bind:value={draft.group}>
          {#each groups as name (name)}
            <option value={name}>{groupLabel(name)}</option>
          {/each}
        </select>
      </label>
      <label>{t(prefs.lang, "c.id")}
        <input type="text" bind:value={draft.id}>
      </label>
      <label>{t(prefs.lang, "c.name")}
        <input type="text" bind:value={draft.name}>
      </label>
      <label>{t(prefs.lang, "c.source")}
        <span class="ep">
          <select bind:value={draft.srcKind}>
            {#each ENDPOINT_KINDS as kind (kind)}
              <option value={kind}>{endpointKind(prefs.lang, kind)}</option>
            {/each}
          </select>
          <input type="text" bind:value={draft.srcValue}>
        </span>
      </label>
      <label>{t(prefs.lang, "c.destination")}
        <span class="ep">
          <select bind:value={draft.dstKind}>
            {#each ENDPOINT_KINDS as kind (kind)}
              <option value={kind}>{endpointKind(prefs.lang, kind)}</option>
            {/each}
          </select>
          <input type="text" bind:value={draft.dstValue}>
        </span>
      </label>
      <label>{t(prefs.lang, "c.proto")}
        <select bind:value={draft.proto}>
          {#each PROTOS as proto (proto)}
            <option value={proto}>{protoWord(prefs.lang, proto)}</option>
          {/each}
        </select>
      </label>
      <label>{t(prefs.lang, "c.ports")}
        <input type="text" bind:value={draft.ports} placeholder={t(prefs.lang, "m.portsEmpty")}>
      </label>
      <label>{t(prefs.lang, "c.action")}
        <select bind:value={draft.action}>
          {#each ACTIONS as action (action)}
            <option value={action}>{t(prefs.lang, action === "allow" ? "v.allow" : "v.deny")}</option>
          {/each}
        </select>
      </label>
      <label>{t(prefs.lang, "c.deny")}
        <select bind:value={draft.denyMode}>
          {#each DENY_MODES as mode (mode || "none")}
            <option value={mode}>{mode ? denyModeWord(prefs.lang, mode) : "—"}</option>
          {/each}
        </select>
      </label>
      <label>{t(prefs.lang, "c.pri")}
        <input type="number" bind:value={draft.priority}>
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={draft.enabled}>
        {t(prefs.lang, "m.enabled")}
      </label>
      <label>{t(prefs.lang, "c.notes")}
        <textarea rows="4" bind:value={draft.notes}></textarea>
      </label>
    </div>
    <footer class="modal-ft">
      <button type="button" onclick={oncancel}>{t(prefs.lang, "m.cancel")}</button>
      <button type="submit">{t(prefs.lang, "m.apply")}</button>
    </footer>
  </form>
</dialog>

<style>
  dialog.modal {
    width: min(520px, calc(100vw - 32px));
    max-height: calc(100vh - 48px);
    padding: 0;
    border: 1px solid var(--bd-2);
    border-radius: var(--r-lg);
    background: var(--surface-overlay);
    box-shadow: var(--sh-overlay);
    color: var(--text-1);
  }
  dialog.modal::backdrop {
    background: var(--surface-scrim);
    backdrop-filter: blur(var(--scrim-blur));
  }
  form {
    display: flex;
    flex-direction: column;
    max-height: calc(100vh - 48px);
  }
  .modal-hd {
    padding: 12px 16px;
    border-bottom: 1px solid var(--bd-1);
  }
  .modal-hd h3 {
    margin: 0;
    font-size: 13.5px;
    font-weight: 600;
  }
  .modal-hd .sub {
    margin: 4px 0 0;
    font-size: 11.5px;
    color: var(--text-3);
  }
  .modal-body {
    padding: 16px;
    overflow: auto;
    display: grid;
    gap: 10px;
  }
  .modal-body label {
    display: grid;
    gap: 4px;
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-3);
  }
  .modal-body .check {
    grid-template-columns: auto 1fr;
    align-items: center;
    letter-spacing: 0;
    text-transform: none;
    color: var(--text-1);
    font-size: 12px;
  }
  .ep {
    display: flex;
    gap: 6px;
  }
  .ep select { flex: 0 0 9rem; }
  .ep input { flex: 1; min-width: 0; }
  textarea { width: 100%; min-height: 5rem; }
  .modal-ft {
    padding: 11px 16px;
    border-top: 1px solid var(--bd-1);
    display: flex;
    justify-content: flex-end;
    gap: 7px;
    background: var(--surface-sunken);
  }
</style>
