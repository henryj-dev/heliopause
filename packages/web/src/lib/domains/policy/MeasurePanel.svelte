<script lang="ts">
  // The labels, read off the cluster, inside the editor that is about to write them into a rule.
  //
  // The panel is deliberately not a picker that fills a field and closes. The operator sees the
  // whole label set, sees which ones were left out and why, and ticks what the selector pins — so a
  // rule that names only the workload's name becomes a choice somebody made rather than the default
  // that happened. `src/kube-read.ts` has the story of what that default costs.
  import { onMount } from "svelte";
  import { t } from "$lib/i18n";
  import { chromePrefs } from "$lib/shell/prefs.svelte";
  import { droppedLabelCount, probeWords, readMeasureReply, selectorText, type Measurement } from "./measure.ts";

  const prefs = chromePrefs();

  // No CSRF token here, and that is not an omission: the manager checks it on POST only, because a
  // read cannot change anything and a token on a GET would be one more thing to keep in sync.
  let { onpick }: { onpick: (where: "src" | "dst", selector: string) => void } = $props();

  let namespaces = $state<string[]>([]);
  let ns = $state("");
  let found = $state<Measurement | null>(null);
  /** Ticked label keys, per pod name. Seeded from the manager's suggestion the first time a pod arrives. */
  let ticked = $state<Record<string, string[]>>({});
  let busy = $state(false);
  let note = $state("");
  let off = $state(false);

  async function ask(namespace: string): Promise<void> {
    busy = true;
    note = "";
    try {
      const res = await fetch(`/api/policy/measure${namespace ? `?ns=${encodeURIComponent(namespace)}` : ""}`, {
        credentials: "same-origin",
      });
      // A console with no cluster credential answers 404, and that is not an error to show in red —
      // it is a deployment that was never granted this. The panel says so once and stays quiet.
      if (res.status === 404) {
        off = true;
        return;
      }
      const reply = readMeasureReply(await res.json());
      if (!reply.ok) {
        note = "reason" in reply ? reply.reason : t(prefs.lang, reply.key);
        return;
      }
      namespaces = reply.measurement.namespaces;
      if (namespace) {
        found = reply.measurement;
        const seeded: Record<string, string[]> = {};
        for (const pod of reply.measurement.pods) seeded[pod.name] = [...pod.suggested];
        ticked = seeded;
      }
    } catch (e) {
      note = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void ask("");
  });

  function toggle(pod: string, key: string): void {
    const now = ticked[pod] ?? [];
    ticked = { ...ticked, [pod]: now.includes(key) ? now.filter((k) => k !== key) : [...now, key] };
  }

  function textFor(podName: string, labels: Record<string, string>): string {
    return selectorText(found?.namespace ?? "", labels, ticked[podName] ?? []);
  }
</script>

{#if off}
  <p class="dim">{t(prefs.lang, "m.measureOff")}</p>
{:else}
  <div class="measure">
    <p class="dim">{t(prefs.lang, "m.measureSub")}</p>
    <p class="act">
      <label>
        {t(prefs.lang, "m.namespace")}
        <select bind:value={ns}>
          <option value=""></option>
          {#each namespaces as name (name)}
            <option value={name}>{name}</option>
          {/each}
        </select>
      </label>
      <button type="button" disabled={busy || !ns} onclick={() => void ask(ns)}>
        {t(prefs.lang, "m.measureLoad")}
      </button>
    </p>

    {#if note}
      <p class="bad">{note}</p>
    {/if}

    {#if found}
      {#if found.pods.length === 0}
        <p class="dim">{t(prefs.lang, "m.measureNone", { ns: found.namespace })}</p>
      {/if}
      {#each found.pods as pod (pod.name)}
        <div class="pod">
          <h4>
            <code>{pod.name}</code>
            {#if pod.ports.length > 0}<span class="dim"> · {pod.ports.join(", ")}</span>{/if}
          </h4>
          <p class="dim small">
            {#if probeWords(pod).length === 0}
              {t(prefs.lang, "m.probesNone")}
            {:else}
              {t(prefs.lang, "m.probesSome", { which: probeWords(pod).join(", ") })}
            {/if}
            {#if droppedLabelCount(pod) > 0}
              · {t(prefs.lang, "m.volatileLeftOut", { n: droppedLabelCount(pod) })}
            {/if}
          </p>
          <ul class="labels">
            {#each Object.entries(pod.stable) as [key, value] (key)}
              <li>
                <label>
                  <input
                    type="checkbox"
                    checked={(ticked[pod.name] ?? []).includes(key)}
                    onchange={() => toggle(pod.name, key)}
                  >
                  <code>{key}={value}</code>
                </label>
              </li>
            {/each}
          </ul>
          <p class="built"><code>{textFor(pod.name, pod.stable)}</code></p>
          <p class="act">
            <button type="button" onclick={() => onpick("src", textFor(pod.name, pod.stable))}>
              {t(prefs.lang, "m.useAsSource")}
            </button>
            <button type="button" onclick={() => onpick("dst", textFor(pod.name, pod.stable))}>
              {t(prefs.lang, "m.useAsDestination")}
            </button>
          </p>
        </div>
      {/each}

      {#if found.services.length > 0}
        <h4>{t(prefs.lang, "m.services")}</h4>
        <ul class="svc">
          {#each found.services as svc (svc.name)}
            <li>
              <code>{svc.name}</code>
              <span class="dim"> · {svc.clusterIP ?? "—"}{#if svc.ports.length > 0} · {svc.ports.map((p) => `${p.protocol}/${p.port}`).join(", ")}{/if}</span>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .measure { display: grid; gap: 8px; }
  .pod { border: 1px solid var(--bd-2); border-radius: var(--r-md); padding: 8px; display: grid; gap: 6px; }
  .pod h4 { margin: 0; }
  .small { font-size: 11px; }
  .labels, .svc { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
  .labels code { font-size: 11px; }
  .built code { font-size: 11px; word-break: break-all; }
</style>
