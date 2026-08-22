<script>
  import { page } from "$app/state";
  import ChangesScreen from "$lib/domains/changes/ChangesScreen.svelte";
</script>

<ChangesScreen asked={page.params.hash ?? ""} />
