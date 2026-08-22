<script>
  import { page } from "$app/state";
  import PolicyScreen from "$lib/domains/policy/PolicyScreen.svelte";
</script>

<PolicyScreen asked={page.params.section ?? ""} />
