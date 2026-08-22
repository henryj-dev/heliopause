<script lang="ts">
  import { onMount } from "svelte";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { writeIsReady, type WriteSpec } from "./write-ask";

  let {
    spec,
    onsubmit,
    oncancel,
  }: {
    spec: WriteSpec;
    onsubmit: (input: { reason: string; otp: string }) => void;
    oncancel: () => void;
  } = $props();

  const prefs = chromePrefs();
  let dialog: HTMLDialogElement | undefined = $state();
  let reasonField: HTMLTextAreaElement | undefined = $state();
  let otpField: HTMLInputElement | undefined = $state();
  let submitBtn: HTMLButtonElement | undefined = $state();
  let reason = $state("");
  let code = $state("");
  const ready = $derived(writeIsReady({ reason, otp: code }, spec));

  onMount(() => {
    dialog?.showModal();
    (reasonField ?? otpField ?? submitBtn)?.focus();
    return () => dialog?.close();
  });

  function send(): void {
    if (!ready) return;
    onsubmit({ reason, otp: code });
  }
</script>

<dialog
  bind:this={dialog}
  class="modal"
  class:wide={spec.reason}
  oncancel={(e) => {
    e.preventDefault();
    oncancel();
  }}
>
  <form
    method="dialog"
    onsubmit={(e) => {
      e.preventDefault();
      send();
    }}
  >
    <header class="modal-hd">
      <h3>{spec.what}</h3>
      {#if spec.needsOtp}
        <p class="sub">{t(prefs.lang, "m.otpSub")}</p>
      {:else}
        <p class="sub">{t(prefs.lang, "m.writeSub")}</p>
      {/if}
    </header>
    <div class="modal-body">
      {#if spec.warning}
        <p class="warn">{spec.warning}</p>
      {/if}
      {#if spec.reason}
        <label>
          {spec.reasonLabel ?? t(prefs.lang, "m.reason")}
          <textarea bind:this={reasonField} name="reason" bind:value={reason} rows="3"></textarea>
        </label>
      {/if}
      {#if spec.needsOtp}
        <label>
          {t(prefs.lang, "m.otpCode")}
          <input
            bind:this={otpField}
            class="otp"
            name="otp"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            spellcheck="false"
            bind:value={code}
          >
        </label>
      {/if}
    </div>
    <footer class="modal-ft">
      <button type="button" onclick={oncancel}>{t(prefs.lang, "m.cancel")}</button>
      <button bind:this={submitBtn} type="submit" disabled={!ready}>
        {spec.needsOtp ? t(prefs.lang, "m.otpSubmit") : t(prefs.lang, "m.writeSubmit")}
      </button>
    </footer>
  </form>
</dialog>

<style>
  dialog.modal {
    width: min(420px, calc(100vw - 32px));
    padding: 0;
    border: 1px solid var(--bd-2);
    border-radius: var(--r-lg);
    background: var(--surface-overlay);
    box-shadow: var(--sh-overlay);
    color: var(--text-1);
  }
  dialog.modal.wide { width: min(480px, calc(100vw - 32px)); }
  dialog.modal::backdrop {
    background: var(--surface-scrim);
    backdrop-filter: blur(var(--scrim-blur));
  }
  form {
    display: flex;
    flex-direction: column;
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
    display: grid;
    gap: 12px;
  }
  .modal-body .warn {
    margin: 0;
    white-space: pre-wrap;
    font-size: 12.5px;
    color: var(--warn-fg);
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
  .modal-body textarea {
    font-family: inherit;
    font-size: 13px;
    letter-spacing: 0;
    text-transform: none;
    resize: vertical;
  }
  .modal-body input.otp {
    font-family: var(--font-mono);
    font-size: 18px;
    letter-spacing: 0.2em;
    font-variant-numeric: tabular-nums;
  }
  .modal-ft {
    padding: 11px 16px;
    border-top: 1px solid var(--bd-1);
    display: flex;
    justify-content: flex-end;
    gap: 7px;
    background: var(--surface-sunken);
  }
</style>
