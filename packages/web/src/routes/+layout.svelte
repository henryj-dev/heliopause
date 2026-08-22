<script>
  import AppShell from "$lib/shell/AppShell.svelte";
  let { children } = $props();
</script>

<AppShell>
  {@render children()}
</AppShell>

