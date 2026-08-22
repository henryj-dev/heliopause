<script lang="ts">
  let { kind = "mute", hatch = false, children }: {
    kind?: "ok" | "warn" | "bad" | "info" | "mute" | "none";
    hatch?: boolean;
    children: import("svelte").Snippet;
  } = $props();
</script>

<span class="chip {kind}" class:hatch={hatch || kind === "none"}>{@render children()}</span>
