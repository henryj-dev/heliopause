<script lang="ts">
  import { onMount } from "svelte";
  import { base } from "$app/paths";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import WriteDialog from "$lib/shell/WriteDialog.svelte";
  import { writeAsk } from "$lib/shell/write-ask.svelte";
  import { loginHref, shouldAskOtp } from "$lib/shell/who";
  import { whoQuery } from "$lib/shell/who.svelte";
  import { errorText, readAdminWrite, type Refusal } from "./answer";
  import {
    INVITES_PATH,
    inviteBody,
    inviteMailNote,
    MEMBERS_PATH,
    planRequest,
    readLink,
    readMembers,
    ROLE_KEY,
    ROLES,
    STATUS_KEY,
    type MemberRow,
    type PanelRequest,
  } from "./members";
  import MemberPanel from "./MemberPanel.svelte";
  import RefusalNote from "./RefusalNote.svelte";
  import { writeHeaders } from "./write";

  type ListState =
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ok"; members: MemberRow[] };

  const prefs = chromePrefs();
  const who = whoQuery();
  const write = writeAsk();
  let list = $state<ListState>({ kind: "loading" });
  let open = $state<string | null>(null);
  let busy = $state(false);
  let refusal = $state<Refusal | null>(null);
  let note = $state("");
  let revealed = $state<{ url: string; note: string } | null>(null);
  let revealedAck = $state(false);
  let email = $state("");
  let inviteRoles = $state<string[]>(["reader"]);

  const view = $derived(who.state.kind === "ok" ? who.state.view : null);
  const isAdmin = $derived(view?.isAdmin === true);

  async function load(): Promise<void> {
    try {
      const res = await fetch(MEMBERS_PATH, { credentials: "same-origin" });
      const body: unknown = await res.json().catch(() => null);
      list = res.ok ? { kind: "ok", members: readMembers(body) } : { kind: "error", message: errorText(body) || `HTTP ${res.status}` };
    } catch (e) {
      list = { kind: "error", message: e instanceof Error ? e.message : String(e) };
    }
  }

  // Read once the chrome says this caller administers members; a non-admin never asks.
  let loaded = false;
  $effect(() => {
    if (isAdmin && !loaded) {
      loaded = true;
      void load();
    }
  });

  onMount(() => () => write.cancel());

  /**
   * One write: the code dialog, the POST with the CSRF header, then the answer. The server's reply
   * when it went through, null when it was cancelled or refused (the refusal is then on the screen).
   */
  async function send(what: string, path: string, body: (otp: string) => string): Promise<unknown> {
    const answer = await write.ask({ what, needsOtp: shouldAskOtp(view) });
    if (answer === null) return null;
    busy = true;
    refusal = null;
    note = "";
    try {
      const res = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: writeHeaders(view?.csrf ?? null),
        body: body(answer.otp),
      });
      const reply: unknown = await res.json().catch(() => null);
      refusal = readAdminWrite(res.status, reply);
      if (refusal) return null;
      const ended = (reply as { endedSessions?: unknown } | null)?.endedSessions;
      note = t(prefs.lang, "m.mmDone", { n: typeof ended === "number" ? ended : 0 });
      await load();
      return reply ?? {};
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
      return null;
    } finally {
      busy = false;
    }
  }

  function reveal(url: string | null, text: string): void {
    if (!url) return;
    revealed = { url, note: text };
    revealedAck = false;
  }

  async function invite(): Promise<void> {
    if (email.trim() === "") return void (refusal = { key: "m.mmNeedEmail", detail: "", problems: [] });
    if (inviteRoles.length === 0) return void (refusal = { key: "m.mmNeedRole", detail: "", problems: [] });
    const to = email.trim();
    const roles = [...inviteRoles];
    const reply = await send(t(prefs.lang, "m.mmWhatInvite", { email: to }), INVITES_PATH, (otp) => inviteBody(to, roles, otp));
    if (reply === null) return;
    const mailNote = inviteMailNote(reply);
    reveal(readLink(reply, "inviteUrl"), t(prefs.lang, mailNote.key, mailNote.params));
    email = "";
  }

  async function request(member: MemberRow, r: PanelRequest): Promise<void> {
    const plan = planRequest(member, r);
    const reply = await send(t(prefs.lang, plan.what.key, plan.what.params), plan.path, plan.body);
    if (reply !== null && plan.link) reveal(readLink(reply, plan.link), t(prefs.lang, "m.mmResetNoMail"));
  }

  async function copyRevealed(): Promise<void> {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.url);
    } catch (e) {
      refusal = { key: "m.mbFailed", detail: e instanceof Error ? e.message : String(e), problems: [] };
    }
  }
</script>

<svelte:head>
  <title>{t(prefs.lang, "page.title.members")}</title>
</svelte:head>

{#if who.state.kind === "loading"}
  <p class="dim">{t(prefs.lang, "m.mmReading")}</p>
{:else if who.state.kind === "unauth"}
  <p><a href={loginHref(`${base}/members`)}>{t(prefs.lang, "m.signIn")}</a></p>
{:else if !isAdmin}
  <p>{t(prefs.lang, "m.mmNotAdmin")}</p>
{:else}
  {#if refusal}
    <RefusalNote {refusal} />
  {/if}

  {#if revealed}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.mmLinkOnce")}</div>
      <p>{revealed.note}</p>
      <p><code class="name">{revealed.url}</code></p>
      <p class="act">
        <button type="button" onclick={() => void copyRevealed()}>{t(prefs.lang, "m.copy")}</button>
        <label>
          <input type="checkbox" bind:checked={revealedAck}>
          {t(prefs.lang, "m.tokenAck")}
        </label>
        <button type="button" disabled={!revealedAck} onclick={() => (revealed = null, revealedAck = false)}>
          {t(prefs.lang, "m.tokenDismiss")}
        </button>
      </p>
    </div>
  {/if}

  <h2>{t(prefs.lang, "m.mmInvite")}</h2>
  <p class="act">
    <input type="email" bind:value={email} placeholder={t(prefs.lang, "m.mmInviteEmail")} aria-label={t(prefs.lang, "m.mmInviteEmail")}>
    {#each ROLES as role (role)}
      <label><input type="checkbox" bind:group={inviteRoles} value={role}> {t(prefs.lang, ROLE_KEY[role])}</label>
    {/each}
    <button type="button" disabled={busy} onclick={() => void invite()}>{t(prefs.lang, "m.mmInviteSubmit")}</button>
  </p>

  <h2>{t(prefs.lang, "nav.members")}</h2>
  {#if list.kind === "loading"}
    <p class="dim">{t(prefs.lang, "m.mmReading")}</p>
  {:else if list.kind === "error"}
    <div class="banner bad">
      <div class="lead">{t(prefs.lang, "m.mmError", { message: list.message })}</div>
      <p class="act"><button type="button" onclick={() => void load()}>{t(prefs.lang, "m.reread")}</button></p>
    </div>
  {:else if list.members.length === 0}
    <div class="empty-card"><p>{t(prefs.lang, "m.mmEmpty")}</p></div>
  {:else}
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>{t(prefs.lang, "m.mmUser")}</th>
            <th>{t(prefs.lang, "m.mmName")}</th>
            <th>{t(prefs.lang, "m.mmEmail")}</th>
            <th>{t(prefs.lang, "m.mmRoles")}</th>
            <th>{t(prefs.lang, "m.mmStatus")}</th>
            <th>{t(prefs.lang, "m.mmOtp")}</th>
            <th>{t(prefs.lang, "m.mmCerts")}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each list.members as member (member.id)}
            <tr>
              <td><code>{member.username}</code>{#if member.principalName === view?.you} <span class="chip">{t(prefs.lang, "m.mmYou")}</span>{/if}</td>
              <td>{member.principalName}</td>
              <td>{member.email ?? ""}</td>
              <td>{member.roles.join(", ")}</td>
              <td>
                {STATUS_KEY[member.status] ? t(prefs.lang, STATUS_KEY[member.status]!) : member.status}
                {#if member.mustChange}<span class="chip warn">{t(prefs.lang, "m.mmMustChange")}</span>{/if}
              </td>
              <td>
                {#if member.otpUserId}
                  <code>{member.otpUserId}</code>
                  <span class="chip">{t(prefs.lang, member.otpConfirmedAt ? "m.mmOtpConfirmed" : "m.mmOtpUnconfirmed")}</span>
                {/if}
              </td>
              <td>{member.certCNs.join(", ")}</td>
              <td>
                {#if member.status !== "deleted"}
                  <button type="button" onclick={() => (open = open === member.id ? null : member.id)}>
                    {t(prefs.lang, open === member.id ? "m.mmClose" : "m.mmManage")}
                  </button>
                {/if}
              </td>
            </tr>
            {#if open === member.id}
              <tr>
                <td colspan="8">
                  {#key member}
                    <MemberPanel {member} {busy} onrequest={(r) => void request(member, r)} />
                  {/key}
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if note}
    <p>{note}</p>
  {/if}
{/if}

{#if write.pending}
  <WriteDialog spec={write.pending.spec} onsubmit={write.submit} oncancel={write.cancel} />
{/if}
