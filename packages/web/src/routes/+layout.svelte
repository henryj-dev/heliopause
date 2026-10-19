<script>
  import { base } from "$app/paths";
  import { page } from "$app/state";
  import AppShell from "$lib/shell/AppShell.svelte";
  import PublicShell from "$lib/shell/PublicShell.svelte";
  import { isPublicPath } from "$lib/shell/nav";
  let { children } = $props();
</script>

{#if isPublicPath(page.url.pathname, base)}
  <PublicShell>
    {@render children()}
  </PublicShell>
{:else}
  <AppShell>
    {@render children()}
  </AppShell>
{/if}
