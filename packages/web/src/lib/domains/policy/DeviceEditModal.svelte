<script lang="ts">
  // One approved device, as a form.
  //
  // The fields are plain text rather than validated inputs, and that is deliberate: `policy/devices.ts`
  // is the authority on what a device row may contain, and it refuses at render time where a bad row
  // stops the render instead of shipping a rule. A second set of rules here would be a weaker copy in
  // front of the user, free to drift from the one that decides.
  //
  // What the form does instead is make the shape legible — each field named, `notes` given room, and
  // the hints below saying what the renderer will insist on. A save that violates one comes back as a
  // failed check on the pull request, which is the place that cannot be bypassed.
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import type { DeviceDraft } from "./devices";

  const prefs = chromePrefs();

  let {
    draft,
    title,
    onapply,
    oncancel,
  }: {
    draft: DeviceDraft;
    title: string;
    onapply: () => void;
    oncancel: () => void;
  } = $props();
</script>

<div class="scrim" role="presentation" onclick={oncancel}></div>
<div class="modal" role="dialog" aria-modal="true" aria-label={title}>
  <h2>{title}</h2>

  <label>
    {t(prefs.lang, "c.device")}
    <input bind:value={draft.deviceName} spellcheck="false" />
  </label>

  <label>
    {t(prefs.lang, "c.user")}
    <input bind:value={draft.userEmail} spellcheck="false" inputmode="email" />
  </label>

  <label class="mono-field">
    deviceId
    <input bind:value={draft.deviceId} spellcheck="false" placeholder="00000000-0000-0000-0000-000000000000" />
    <!-- Cloudflare assigns this. It is the join key the drift check compares against, so a hand-typed
         one is the field most likely to be wrong in a way nothing else notices. -->
    <small>{t(prefs.lang, "ed.deviceIdHint")}</small>
  </label>

  <div class="pair">
    <label class="mono-field">
      {t(prefs.lang, "c.v4")}
      <input bind:value={draft.v4} spellcheck="false" placeholder="10.0.0.1" />
    </label>
    <label class="mono-field">
      {t(prefs.lang, "c.v6")}
      <input bind:value={draft.v6} spellcheck="false" placeholder="2001:db8::1" />
    </label>
  </div>

  <label class="wide">
    {t(prefs.lang, "ed.deviceNotes")}
    <textarea bind:value={draft.notes} rows="4" spellcheck="false"></textarea>
    <!-- Empty is normal: most rows need no argument. The three that have one needed it — a phone that
         grants console access, a tablet found beside 53 orphans, a gateway whose last_seen_at can
         never refresh. Clearing this box removes the key rather than storing "". -->
    <small>{t(prefs.lang, "ed.deviceNotesHint")}</small>
  </label>

  <p class="acts">
    <button type="button" onclick={onapply}>{t(prefs.lang, "m.apply")}</button>
    <button type="button" onclick={oncancel}>{t(prefs.lang, "m.cancel")}</button>
  </p>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: color-mix(in srgb, var(--bg-0) 70%, transparent);
    z-index: 40;
  }
  .modal {
    position: fixed;
    inset-block-start: 50%;
    inset-inline-start: 50%;
    translate: -50% -50%;
    z-index: 41;
    display: grid;
    gap: 10px;
    width: min(560px, calc(100vw - 32px));
    max-height: calc(100vh - 48px);
    overflow: auto;
    padding: 16px;
    background: var(--bg-1);
    border: 1px solid var(--line);
    border-radius: var(--radius);
  }
  h2 { margin: 0; font-size: 14px; }
  label { display: grid; gap: 4px; font-size: 11px; color: var(--text-2); }
  .pair { display: grid; gap: 10px; grid-template-columns: 1fr 1fr; }
  .mono-field input { font-family: var(--font-mono); }
  small { color: var(--text-2); font-size: 10px; }
  .acts { display: flex; gap: 8px; margin: 4px 0 0; }
  .acts button { height: var(--ctl-h); }
</style>
