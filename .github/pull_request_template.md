## What was wrong

<!--
The state of the world before this change, not a summary of the diff — the diff already says what
changed. If a defect was measured, the measurement belongs here.
-->

## Why this is the fix

<!-- What would have to be true for this to be the wrong fix, and why it isn't. -->

## Checks

<!-- See CONTRIBUTING.md. Delete the lines that do not apply and say why in the box below. -->

- [ ] `npm run typecheck && npm test`
- [ ] `python3 agent/test_validate.py && python3 agent/test_enroll.py`
- [ ] New tests verified to **fail** against the defect they cover — introduce it, watch the test
      catch it, revert. A regression test that passes against broken code certifies nothing.
- [ ] No site-specific data in a tracked file. Documentation ranges (`192.0.2.0/24`) and RFC 2606
      names (`example.com`) in tests and examples.
- [ ] Comments say *why*, and name what was measured where something was.

<!--
`./scripts/e2e-roundtrip.sh` and `./scripts/rollback-test.sh` need openssl/curl and docker
respectively. CI runs both on every pull request, so running them locally is optional — reading
their result is not.
-->

## Anything a reviewer would otherwise have to discover

<!--
A narrowed rule, a check that now behaves differently on the failure path, a comment that was
promising something the code did not do. This section is where a review gets cheap or expensive.

Security-relevant behaviour — anything touching what a host accepts, identity binding, revocation,
or the rollback timer — say so plainly here. If the change *is* a vulnerability fix, it belongs in a
private advisory first: see SECURITY.md.
-->
