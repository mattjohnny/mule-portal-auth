# C2 verification harness re-review

Additive follow-up to `c2-transport-review-2026-09-22.md`, after parent review of
head `081dba1afefe4b87a92b182bea4265471862b277` (tree
`57802110583cb9cb2d7aaa17179eda902ebfe0f4`). Parent independently reproduced the
original focused 7/7 and full 101/101 tests and matching emitted artifact, but
held merge for a confirmed mutation-classifier gap: missing per-mutant module
preflight and complete TAP validation, plus an outer assertion that could mask
a TLS child crash. The original saved mutation logs are actual complete
behavioral assertion failures; they are preserved unchanged, not retracted.

## Narrow repair

- Syntax-check and import the mutated emitted transport (and public index) before
  every mutation test, recording both steps. A failing preflight cannot count as
  a killed mutant.
- Validate the exact seven outer test identities/order, one plan, complete
  records, sane exit and pass/fail totals, and zero cancellations/skips/todos.
  Each failed record must carry its own top-level behavioral assertion diagnostic;
  a stray nested ERR_ASSERTION string is insufficient. The exact expected failing
  test set must match, not merely a subset of matching titles.
- Retain a complete TLS child result in a TAP diagnostic receipt. Validate the
  child independently, including its exact one-test census, actual assertion,
  exit, stderr and process error/signal status, and require inner/outer TLS
  outcomes to agree. Invalid child evidence throws an ordinary Error rather than
  becoming an outer behavioral AssertionError.
- The local development test converts only the expected HTTPS-policy denial into
  an assertion; unrelated runtime/outage errors propagate.
- Never overwrite a proof output folder. Write `completion.json` only after the
  restored module preflight and complete restored baseline pass. Partial
  `mutations.json` alone does not claim completed verification.

No transport source, compiled artifact, package manifest/lock, policy, tag or
consumer changes. Emitted `portal.js` SHA-256 remains
`b04ba3cda50ea7f7d939f6da3ff02ec4a9b9d7b309674781cb7ccebc1019204d`.

## Evidence

`evidence/c2-2026-09-22-harness-r3/` contains the completed corrected run:

- All nine original mutants assertion-killed; each has successful syntax/import
  preflight, exact outer failure census and independently validated TLS receipt.
  Preflight and restored suites passed, and exact byte restoration is true in
  `completion.json`.
- Fifty classifier self-tests pass. Invalid outer and child cases include load
  errors, TypeErrors, timeouts, signals, abnormal exits, missing/duplicate plan or
  totals, mismatched pass/fail totals, cancellations/skips/todos, missing records,
  wrong identities, bailouts, missing/duplicate/malformed child receipts, and
  outer/inner mismatch. The invalid-child cases retain a superficially valid
  outer AssertionError to exercise the original false-kill mechanism.
- Four classifier mutations in an isolated temporary copy were assertion-killed:
  ignore process errors, ignore summary counts, ignore assertion kind, and ignore
  child evidence. Exact failed test identities and logs are retained, alongside
  the local reproduction script. The repository classifier was never mutated.
- Typecheck, full package suite **151/151** (zero failures/cancellations/skips),
  and separate build passed on Node22.23.2 with dot-free temp and explicit PATH.
  The committed original evidence directory and transport source/dist have no
  content diff from the reviewed prior head.

`evidence/c2-2026-09-22-harness-r2/` preserves the incomplete first stricter run:
Node escaped the stdout marker, so the classifier rejected the otherwise passing
preflight as missing a TLS receipt. Zero mutations were credited. The marker was
changed to `t.diagnostic`, and a fresh folder was used for the complete run.
Saved logs normalize only trailing whitespace and terminal blank lines.

Independent read-only security re-review found no remaining confirmed classifier
bypass for this fixed catalog. It also identified the broad development wrapper
and missing completion receipt; both were corrected and re-reviewed. It did not
independently rerun tests. Parent exact-head review/CI acceptance remains required.
The parser intentionally accepts these flat Node TAP suites, not arbitrary TAP.
Timed proof observations and source-traced stale-session/Google paths remain the
previous bounded coverage limitations. All later adoption/deployment gates from
the original record remain unchanged; Accountability C2 is not terminal here.
