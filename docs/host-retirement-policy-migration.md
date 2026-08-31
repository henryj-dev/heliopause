# Host retirement policy worker migration

The manager deliberately does not parse or rewrite a TypeScript policy module. Its production image
contains no TypeScript parser, and editing a brace-delimited `site.hosts` block with text matching can
remove the wrong host while still producing valid policy.

Before enabling `HELIOPAUSE_POLICY_RETIREMENTS_PATH`, make one reviewed change in each policy
repository served by that manager:

1. Add a machine-owned file, normally `retired-hosts.json`:

   ```json
   {
     "schemaVersion": 1,
     "retiredHosts": []
   }
   ```

2. Import the file and the tracked filter at the policy boundary:

   ```ts
   import RETIRED_HOSTS from "./retired-hosts.json" with { type: "json" };
   import { withoutRetiredHosts } from "../src/retired-hosts.ts";

   const HOSTS = [
     // the existing host objects, unchanged
   ];

   export const site: Site = {
     // the existing fields, unchanged
     hosts: withoutRetiredHosts(HOSTS, RETIRED_HOSTS),
   };
   ```

3. Add `retired-hosts.json` to both `HELIOPAUSE_POLICY_EDITABLE` and
   `HELIOPAUSE_POLICY_ALLOW_PATHS`. The manager refuses to start the worker when the write allowlist
   omits it; the worker will retry without advancing when the renderer does not expose it.

4. Deploy with `HELIOPAUSE_POLICY_RETIREMENTS_PATH=retired-hosts.json`. Optionally set
   `HELIOPAUSE_POLICY_WORKER_INTERVAL_MS` (minimum 1000; default 30000).

Each JSON row binds the exact hostname to its lifecycle id, external destroy operation id and
infrastructure destruction timestamp. Replay accepts only the same tuple; a second lifecycle trying
to retire the same hostname is refused. The list suppresses only an exact `PublishHost.id`. Address tables, measurement history and
policy catalogue notes remain for review and can be cleaned in a later human change. The removal PR
does not publish. A human still reviews and merges the source PR, then approves and publishes the
ordinary rendered plan with the existing OTP/two-person gate. The worker merely reconstructs that
plan after a restart and waits until every configured relay independently reports a manifest without
the hostname.

Do not point the worker at `dev.ts`, and do not enable it before this migration has merged. The
policy directory in this repository is an ignored shared symlink, so the worker implementation does
not edit it.
