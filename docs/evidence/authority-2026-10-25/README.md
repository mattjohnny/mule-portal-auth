# Local authority contract verification — 2026-10-25

Connector base: `57c199b1f1c0df054bae3955dc7e39afd6a89142`.
Original verified Portal counterpart: `7480482557688ecbae9270edd6d9a7ed435a227b`.
Publication counterpart: `f593c2bc4b4cd57edfb4bf52f4759ff0481f9799` (same runtime
code; local reports omitted). Results below describe the original verification;
fresh publication checks and release gates are recorded in the draft PR.
Package declaration remains `0.2.4`; this is an unreleased local change.

Both connector entrypoints now support explicit `authorityMode: "request"`.
Each protected request fetches current authority without cached context or
in-flight sharing. Responses remain local to their request; a late response
cannot restore a deleted session. Scalar primary roles remain compatible with
older callers. Context claims and the typed, fresh app directory validate roles,
permissions, status, versions, and canonical locations, with non-Mule inclusion
explicitly requested. The main README documents the contract and limits.

## Evidence

| Check | Observed result |
|---|---|
| Clean locked install, emitted build, typecheck | Passed after dependency repair |
| Complete connector suite | 171 passed; no failures, cancellations, or skips |
| Focused real HTTP/Express contract and consumer types | 20 passed |
| Authority mutations | 19/19 killed by named behavioral assertions |
| Existing HTTPS/redirect mutations | 9/9 killed by named behavioral assertions |
| Artifact restoration | Exact bytes restored; both restored suites passed |
| Independent spec and standards review | No confirmed blockers |
| Full npm audit | Before: 3 affected packages / 4 advisories; after: zero |
| Production-only npm audit | Zero before and after |

The cross-repo owner also exercised the real Portal HTTP service and PostgreSQL
session store, including two connector instances and held-response races. Its
initial 14 cases passed; isolated cache-reuse and missing-session-check mutants
failed their intended assertions. Final cross-repo receipts live with the Portal
change and must match the resolved commit above before handover.

Restored emitted SHA-256 fingerprints:

- `dist/index.js`: `c7b3150aa735e1860b7b539d3f87ecf97b7f7a2b817716ced8514544526963bd`
- `dist/portal.js`: `91bd682cd8a9202d9573fba9abc557adec3ceef8b8c83162e28f89b8b4cb3d62`
- `dist/types.d.ts`: `04cb0a5f1eb2adbc129bc8a133fd8bcf4e29670ad100515a8df0913f3bbf9f09`

Run `npm ci --include=dev`, `npm run typecheck`, and `npm test`, then run
`node scripts/verify-authority-mutations.mjs` and
`node scripts/verify-c2-mutations.mjs` sequentially. Mutation runs temporarily
change emitted files; do not run builds or integrations concurrently.

## Dependency repair and limits

The compatible lock-only repair updates `body-parser` 2.3.0 → 2.4.0,
`proxy-addr` 2.0.7 → 2.0.8, and `qs` 6.15.3 → 6.16.1. Body-parser requires the
additional nested `content-type` 2.0.0 → 2.1.0 update. Express stays 5.2.1;
manifest dependency ranges and production AWS dependencies are unchanged. npm
also reconciled stale lock metadata from 0.2.3 to the existing 0.2.4 manifest.

These packages are in this connector's development dependency tree. Consuming
apps supply their own Express peer and need their own lock/audit verification;
this local fix does not establish their adoption or production remediation.
`dependency-paths.json` is the **before-repair** installed dependency snapshot.
Before/after full and production audits, the exact lock diff, all TAP logs, and
mutation receipts are retained locally beside this summary, outside the commit.
An initial mutation run stopped because its expected failure census omitted two
additional valid role-validation assertions; the corrected final run completed
all 19 mutations. Node 24 transport child tests explicitly select TAP so evidence
parsing cannot mistake reporter output for a transport failure.

No tag, release, consumer pin, push, deployment, account change, or production
access change was performed. Release/adoption gates remain separate work.
