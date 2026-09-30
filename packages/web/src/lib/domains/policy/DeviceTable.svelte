<script lang="ts">
  // The approved device registry, as a table instead of a JSON textarea.
  //
  // ## Why this component exists
  //
  // Approving a device used to mean editing `dev.ts` — a TypeScript module — and opening a pull
  // request. Measured twice in three days: an iPad on 2026-09-26 and the homelab gateway on
  // 2026-09-28, each a hand edit for one row of data. `heliopause-deploy#37` moved the rows into
  // `devices.json` so a form could reach them; this is that form.
  //
  // ## Why deletion asks, and asks with the address
  //
  // Removing a row is how an approval is revoked, and the classic console's comment says what that
  // means: `ao-operators` is the union of a person's devices, so deleting a row narrows every rule
  // scoped to them. The confirmation therefore names the address rather than only the device — two
  // machines can share a name (a laptop model name appears twice in this account), and the
  // address is what a rule actually matched on.
  //
  // ⚠️ **A row with no `notes` is not a defect.** Most devices need no argument. The three that carry
  // one needed it, and the gateway's is a standing warning rather than history — `last_seen_at` can
  // never refresh for it, so retiring it by recency would kill a live gateway. The table shows notes
  // inline for exactly that reason: the warning has to be visible where someone would delete the row.
  import { onMount } from "svelte";
  import { t, type MessageKey } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import "./rows.css";
  import DeviceEditModal from "./DeviceEditModal.svelte";
  import {
    addDevice,
    applyDeviceDraft,
    DEVICE_COLUMNS,
    deleteDevice,
    draftFromDevice,
    newDevice,
    type DeviceDoc,
    type DeviceDraft,
    type DeviceRow,
  } from "./devices";

  const prefs = chromePrefs();
  const write = writeAsk();

  let { doc, mark }: { doc: DeviceDoc; mark: () => void } = $props();

  type Editor =
    | { kind: "edit"; row: DeviceRow; draft: DeviceDraft }
    | { kind: "create"; draft: DeviceDraft };

  let editor = $state<Editor | null>(null);

  function openEdit(row: DeviceRow): void {
    editor = { kind: "edit", row, draft: draftFromDevice(row) };
  }

  function openCreate(): void {
    editor = { kind: "create", draft: draftFromDevice(newDevice()) };
  }

  function apply(): void {
    if (!editor) return;
    // Create appends first and then applies, so a half-filled draft cannot leave the document with a
    // row the table did not paint — the same order `RuleTable` uses.
    const row = editor.kind === "create" ? addDevice(doc) : editor.row;
    applyDeviceDraft(row, editor.draft);
    mark();
    editor = null;
  }

  onMount(() => () => write.cancel());

  async function remove(row: DeviceRow): Promise<void> {
    const answer = await write.ask({
      what: t(prefs.lang, "m.delete"),
      warning: t(prefs.lang, "m.deleteDeviceConfirm", {
        name: row.deviceName || row.deviceId || "—",
        addr: row.v4 || "—",
      }),
      needsOtp: false,
    });
    if (answer === null) return;
    if (!deleteDevice(doc, row)) return;
    mark();
  }
</script>

<div class="scroll">
  <table class="policy-rows">
    <thead>
      <tr>
        {#each DEVICE_COLUMNS as heading (heading || "actions")}
          <th>{heading ? t(prefs.lang, heading as MessageKey) : ""}</th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each doc.devices as row (row)}
        <tr>
          <td>
            <span class="name" title={row.deviceName || "—"}>{row.deviceName || "—"}</span>
            <div class="dim id" title={row.deviceId}>{row.deviceId || "—"}</div>
            {#if typeof row.notes === "string" && row.notes}
              <div class="dim notes" title={row.notes}>{row.notes}</div>
            {/if}
          </td>
          <td class="mono">{row.userEmail || "—"}</td>
          <td class="mono">{row.v4 || "—"}</td>
          <td class="mono v6" title={row.v6}>{row.v6 || "—"}</td>
          <td class="acts">
            <button type="button" onclick={() => openEdit(row)}>{t(prefs.lang, "m.edit")}</button>
            <button type="button" onclick={() => void remove(row)}>{t(prefs.lang, "m.delete")}</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
<p class="act">
  <button type="button" onclick={openCreate}>{t(prefs.lang, "m.addDevice")}</button>
</p>

{#if editor}
  <DeviceEditModal
    draft={editor.draft}
    title={editor.kind === "create"
      ? t(prefs.lang, "m.addDevice")
      : t(prefs.lang, "m.editDevice", { name: editor.draft.deviceName || editor.draft.deviceId || "—" })}
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
  /* An IPv6 address is wide enough to push the action buttons off a narrow screen. */
  .v6 { max-width: 18ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .acts button { height: var(--ctl-h); }
</style>
