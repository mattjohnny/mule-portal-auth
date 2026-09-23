# Accountability C2 — shared transport preparation

Stage2a only. Base: `c09be12f6fbd9a797dda52f781635069d0a581c8` (main and v0.2.4).
Branch: `codex/portal-auth-c2-https-20260922`. The draft PR identifies the exact
review head/tree. Package version and lock graph are unchanged. No tag, release,
consumer adoption, deployment or finding closure is authorized by this record.

Basis: fleet-docs `b7a6906f`, staged-go-plan-2026-09-22, selected Security report
`security/apps/accountability-2026-09-22-a0a9d3c.md` and original
`security/apps/accountability.md`, finding `accountability/security/C2`.
Accountability already rejects HTTP in production-equivalent mode. That existing
consumer mitigation does not refute the shared finding.

## Refutation and change

Confirmed in the base compiled package with actual local listeners: each of three
environments (production, Render with NODE_ENV unset, Render with development)
sent 15 HTTP requests, including background credential proof, public sync/async
SSO and directory calls, and credential/legacy context calls. Local development
controls sent the expected synthetic authorization headers, SSO body and handle.
No production service or real credential was used.

The base HTTPS test also followed a redirect (expected 301, received 200).
Checking only the configured URL would leave an HTTPS-to-HTTP redirect path
around the transport policy. The repair therefore refuses HTTP when production
or Render is active, validates direct transport requests before discovering or
attaching credentials, and forces manual redirects on both credential modes,
including background proofs. URL errors remain non-outage PortalErrors. Returned
3xx responses follow the existing non-outage rejection paths; proof cannot promote
a credential from a redirected response.

Compatibility: HTTP remains usable when neither production nor nonempty Render
is present (including unset, development and test NODE_ENV). All redirects are
refused, including HTTPS same-origin redirects; users of aliases must configure
the final URL. There is no redirect allowlist or speculative public option.
Construction remains lazy: the guard applies when making a Portal request, not
as a constructor configuration validator. Existing cached-session grace, Google
policy and outage-only admin policy are unchanged.

## Local proof

Windows, isolated Node22.23.2, explicit Node PATH/npm-cli, dot-free temp. Locked
dependencies were installed by the preparation task; this task additionally
loaded better-sqlite3 and executed an in-memory SELECT successfully, despite the
earlier npm build-approval metadata warning. No dependency graph edits.

- `npm run typecheck`: passed.
- `npm test`: 101 tests passed, zero failed/cancelled/skipped; includes package build.
- Separate `npm run build`: passed; only `dist/portal.js` has a semantic build diff.
- Focused transport suite: 7/7 passed, including a spawned real TLS test with
  certificate verification enabled and a process-scoped localhost trust anchor.
  HTTPS success, 301/302/303/307/308, HTTP downgrade and same-origin targets,
  app-bound and legacy credentials, explicit caller `redirect: follow`, SSO,
  handle context, directory and proof are exercised.
- `node scripts/verify-c2-mutations.mjs`: 9/9 assertion-killed, with successful
  preflight, exact byte restoration and successful restored suite. The mutation
  list and failing test names are in `evidence/c2-2026-09-22/mutations.json`.
  Production guard, Render guard, development compatibility, direct-request
  guard, proof URL guard, credential redirect, legacy redirect, proof redirect
  and outage classification each discriminate.
- Emitted `dist/portal.js` SHA-256 after mutations and the final independent build:
  `b04ba3cda50ea7f7d939f6da3ff02ec4a9b9d7b309674781cb7ccebc1019204d`.
  Reviewed source Git blob: `4c1c4097034efa58f06abf5d76c104e33c6ddfb7`.
  Tests import this compiled artifact; no source-only simulation is claimed.

Baseline, mutation, restored, full-suite, typecheck and build outputs are in
`evidence/c2-2026-09-22/`. Existing unrelated full-suite tests are regression
coverage, not a newly mutation-proven full security assessment.
Only trailing whitespace and terminal blank lines were normalized in saved logs.

## Failed attempts retained

1. Sandbox GitHub fetch failed; permitted network retry succeeded. The isolated
   clone needed a per-command safe.directory exception under the elevated user.
2. Initial nested TLS test inherited NODE_TEST_CONTEXT and falsely returned
   success without running its inner test. The corrected child removes that
   variable and asserts its TAP test/pass census. Both baseline logs are retained;
   corrected baseline is 3 passing development controls / 4 failing security tests.
3. First mutation census stopped after two kills: prohibiting development HTTP
   raised PortalError directly rather than ERR_ASSERTION. The success test now
   uses assert.doesNotReject. First-attempt output and partial census remain beside
   the complete rerun; that failed attempt is not counted as a completed census.
4. Initial generated dist status showed line-ending-only changes in unrelated
   files; normalized Git comparison confirms only the intended transport differs.

## Independent review and limits

Independent security subagent reviewed source and test blobs without editing or
running concurrent tests. Verdict: no confirmed bypass or reproducible suspected
defect; narrow repair acceptable pending package/CI/artifact gates. It traced all
four fetch sites and sync/async convergence, forced manual redirect ordering and
non-outage error preservation. Source blob above is unchanged after that review.

Residual evidence limits: new wire tests do not separately exercise stale-session
middleware or Google sign-in end-to-end (their context path is source-traced;
existing regression tests pass). Proof observations use bounded timed waits;
both proof-guard and proof-redirect mutants were assertion-killed. Provider
discovery can happen before proof URL validation, but no HTTP transmission can.
Local fixtures do not establish actual Portal or consumer deployment behavior.
The package has no independent /health service. Parent retains final exact-head
review and merge gates, and all Accountability claim/canonical updates.

## Later Accountability adoption sequence

1. Parent independently reviews the exact draft head/tree, tests/mutations and
   green exact-head CI; merge only under the staged plan's acceptance authority.
2. Identify an immutable accepted merged package commit (or a separately approved
   future tag). No version/tag/publish action is part of this preparation.
3. After preceding app stages are accepted, create the separate Stage2d consumer
   task from fresh main. Explicitly resolve package and lockfile to that exact
   accepted commit; perform a clean install and inspect the installed artifact.
4. Run full consumer gates plus SSO, revalidation, role/location/session-digest
   regression and production/Render HTTP rejection proof against the installed
   package. Preserve the existing app HTTPS guard and paused weekly locking.
5. Parent reviews/merges the consumer change, verifies the deployed revision
   separately from healthy/read-only Portal behavior, then files finding-specific
   adoption/deployment acceptance. Only then consider C2 terminal in Accountability.
   No other fleet consumer is adopted by this sequence.
