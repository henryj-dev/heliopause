---
name: Bug report
about: Something renders, applies or reports differently than it should
labels: bug
---

## What happened

<!-- What the tool did. -->

## What should have happened

<!-- What you expected instead, and why. -->

## The generation, if there is one

<!--
The generation id and the rendered artifact are the exact input the agent acted on, so they make the
difference between reproducing this and guessing at it.

    node bin/heliopause-publish.ts <site> <dir> --dry-run

**Redact site-specific addresses before pasting**, and never include private keys or certificates.
-->

## Environment

- heliopause version / commit:
- Node version:
- Host OS and kernel:
- nftables version (`nft --version`):
- If it involves the workload layer, Cilium version:

<!--
Security issues — anything that would let someone bypass or disable a deployed ruleset — go to a
private advisory instead. See SECURITY.md.
-->
