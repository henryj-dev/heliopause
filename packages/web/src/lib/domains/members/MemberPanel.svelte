<script lang="ts">
  // One member's actions. The parent sends each write (through the one-time-code dialog); this
  // holds only what is typed or ticked before that, and the in-page delete confirmation.
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { actionsFor, ROLE_KEY, ROLES, type MemberRow, type PanelRequest } from "./members";

  let {
    member,
    busy,
    onrequest,
  }: { member: MemberRow; busy: boolean; onrequest: (request: PanelRequest) => void } = $props();

  const prefs = chromePrefs();
  const actions = $derived(actionsFor(member));
  // Seeded from the row once; the row re-reads after every write and the panel is keyed by id.
  // svelte-ignore state_referenced_locally
  let roles = $state<string[]>([...member.roles]);
  // svelte-ignore state_referenced_locally
  let otpUserId = $state(member.otpUserId ?? "");
  let cn = $state("");
  let confirmingDelete = $state(false);
</script>

<div class="panel">
  {#if actions.includes("roles")}
    <p class="act">
      {#each ROLES as role (role)}
        <label><input type="checkbox" bind:group={roles} value={role}> {t(prefs.lang, ROLE_KEY[role])}</label>
      {/each}
      <button type="button" disabled={busy} onclick={() => onrequest({ action: "roles", roles })}>{t(prefs.lang, "m.mmSaveRoles")}</button>
    </p>
  {/if}

  {#if actions.includes("otp-user")}
    <p class="act">
      <input bind:value={otpUserId} placeholder={t(prefs.lang, "m.mmOtpUser")} aria-label={t(prefs.lang, "m.mmOtpUser")} spellcheck="false">
      <button type="button" disabled={busy || otpUserId.trim() === ""} onclick={() => onrequest({ action: "otp-user", otpUserId })}>{t(prefs.lang, "m.mmOtpSet")}</button>
      {#if member.otpUserId}
        <button type="button" disabled={busy} onclick={() => onrequest({ action: "otp-user", otpUserId: null })}>{t(prefs.lang, "m.mmOtpClear")}</button>
      {/if}
    </p>
    <p class="dim">{t(prefs.lang, "m.mmOtpNote")}</p>
  {/if}

  {#if actions.includes("cert-cns")}
    <p class="act">
      {#each member.certCNs as bound (bound)}
        <code>{bound}</code>
        <button type="button" disabled={busy} onclick={() => onrequest({ action: "cert-cns", change: { remove: bound } })}>{t(prefs.lang, "m.mmCertRemove")}</button>
      {/each}
      <input bind:value={cn} placeholder={t(prefs.lang, "m.mmCertPlaceholder")} aria-label={t(prefs.lang, "m.mmCertPlaceholder")} spellcheck="false">
      <button type="button" disabled={busy || cn.trim() === ""} onclick={() => onrequest({ action: "cert-cns", change: { add: cn } })}>{t(prefs.lang, "m.mmCertAdd")}</button>
    </p>
  {/if}

  {#if actions.includes("solo-approve")}
    <p class="act">
      <span>{t(prefs.lang, member.soloApprove ? "m.mmSoloIsOn" : "m.mmSoloIsOff")}</span>
      <button type="button" disabled={busy} onclick={() => onrequest({ action: "solo-approve", soloApprove: !member.soloApprove })}>
        {t(prefs.lang, member.soloApprove ? "m.mmSoloOff" : "m.mmSoloOn")}
      </button>
    </p>
    <p class="dim">{t(prefs.lang, "m.mmSoloNote")}</p>
  {/if}

  <p class="act">
    {#if actions.includes("suspend")}
      <button type="button" disabled={busy} onclick={() => onrequest({ action: "suspend" })}>{t(prefs.lang, "m.mmSuspend")}</button>
    {/if}
    {#if actions.includes("unsuspend")}
      <button type="button" disabled={busy} onclick={() => onrequest({ action: "unsuspend" })}>{t(prefs.lang, "m.mmUnsuspend")}</button>
    {/if}
    {#if actions.includes("password-reset")}
      <button type="button" disabled={busy} onclick={() => onrequest({ action: "password-reset" })}>{t(prefs.lang, "m.mmReset")}</button>
    {/if}
    {#if actions.includes("delete") && !confirmingDelete}
      <button type="button" disabled={busy} onclick={() => (confirmingDelete = true)}>{t(prefs.lang, "m.mmDelete")}</button>
    {/if}
  </p>

  {#if confirmingDelete}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.mmDeleteConfirm", { name: member.username })}</div>
      <p class="act">
        <button type="button" disabled={busy} onclick={() => { confirmingDelete = false; onrequest({ action: "delete" }); }}>
          {t(prefs.lang, "m.mmDeleteYes", { name: member.username })}
        </button>
        <button type="button" onclick={() => (confirmingDelete = false)}>{t(prefs.lang, "m.cancel")}</button>
      </p>
    </div>
  {/if}
</div>

<style>
  .panel { display: grid; gap: 4px; padding: 8px 0; }
  .panel p { margin: 0; }
  .act { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
</style>
