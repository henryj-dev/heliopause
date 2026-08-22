<script>
  import { page } from "$app/state";
  import EnrollmentScreen from "$lib/domains/enrollment/EnrollmentScreen.svelte";
</script>

<EnrollmentScreen asked={page.params.status ?? ""} />
