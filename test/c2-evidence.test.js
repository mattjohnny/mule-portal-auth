import assert from "node:assert/strict";
import { test } from "node:test";
import { childReceipt, classifyTransportRun, tlsTitle, transportTitles, validateTap } from "../scripts/c2-evidence.mjs";

// Parser fixtures deliberately include the formerly misleading outer
// ERR_ASSERTION wrapper. The inner result, not that wrapper, must prove the kill.
function result(titles, failures = []) {
  return { status: failures.length ? 1 : 0, signal: null, error: null, stderr: "", stdout:
    "TAP version 13\n" + titles.map((title, i) => {
      const failed = failures.includes(title);
      return `${failed ? "not ok" : "ok"} ${i + 1} - ${title}\n  ---\n  type: 'test'\n` +
        (failed ? "  failureType: 'testCodeFailure'\n  code: 'ERR_ASSERTION'\n  name: 'AssertionError'\n" : "") + "  ...\n";
    }).join("") + `1..${titles.length}\n# tests ${titles.length}\n# suites 0\n# pass ${titles.length - failures.length}\n# fail ${failures.length}\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1.5\n` };
}
function transport(child = result([tlsTitle]), failures = []) {
  const outer = result(transportTitles, failures);
  outer.stdout += childReceipt(child);
  return outer;
}
const tlsFailure = [transportTitles[6]];
test("C2 classifier accepts complete success and exact behavioral failure censuses", () => {
  assert.deepEqual(classifyTransportRun(transport()), { failed: [], tlsFailed: [] });
  assert.deepEqual(classifyTransportRun(transport(result([tlsTitle], [tlsTitle]), tlsFailure), tlsFailure), { failed: tlsFailure, tlsFailed: [tlsTitle] });
  const failures = transportTitles.slice(0, 3);
  assert.deepEqual(classifyTransportRun(transport(result([tlsTitle]), failures), failures), { failed: failures, tlsFailed: [] });
});

const invalid = [
  ["timeout", (r) => ({ ...r, error: "ETIMEDOUT" })],
  ["signal", (r) => ({ ...r, signal: "SIGTERM" })],
  ["crash exit", (r) => ({ ...r, status: 2 })],
  ["missing exit", (r) => ({ ...r, status: null })],
  ["exit census mismatch", (r) => ({ ...r, status: 0 })],
  ["stderr runtime error", (r) => ({ ...r, stderr: "uncaught exception" })],
  ["load error", (r) => ({ ...r, stdout: r.stdout.replace("code: 'ERR_ASSERTION'", "code: 'ERR_MODULE_NOT_FOUND'") })],
  ["runtime TypeError", (r) => ({ ...r, stdout: r.stdout.replace("name: 'AssertionError'", "name: 'TypeError'") })],
  ["cancelled failure type", (r) => ({ ...r, stdout: r.stdout.replace("testCodeFailure", "cancelledByParent") })],
  ["hook failure", (r) => ({ ...r, stdout: r.stdout.replace("testCodeFailure", "hookFailed") })],
  ["missing plan", (r) => ({ ...r, stdout: r.stdout.replace(/^1\.\.\d+\n/m, "") })],
  ["duplicate plan", (r) => ({ ...r, stdout: r.stdout + "1..1\n" })],
  ["wrong test count", (r) => ({ ...r, stdout: r.stdout.replace(/# tests \d+/, "# tests 99") })],
  ["wrong pass count", (r) => ({ ...r, stdout: r.stdout.replace(/# pass \d+/, "# pass 99") })],
  ["wrong fail count", (r) => ({ ...r, stdout: r.stdout.replace(/# fail \d+/, "# fail 99") })],
  ["cancelled census", (r) => ({ ...r, stdout: r.stdout.replace("# cancelled 0", "# cancelled 1") })],
  ["skipped census", (r) => ({ ...r, stdout: r.stdout.replace("# skipped 0", "# skipped 1") })],
  ["todo census", (r) => ({ ...r, stdout: r.stdout.replace("# todo 0", "# todo 1") })],
  ["duplicate summary", (r) => ({ ...r, stdout: r.stdout + "# fail 1\n" })],
  ["truncated summary", (r) => ({ ...r, stdout: r.stdout.replace(/# duration_ms .+\n/, "") })],
  ["missing test record", (r) => ({ ...r, stdout: r.stdout.replace(/^(?:not )?ok 1[^]*?^  \.\.\.\n/m, "") })],
  ["unknown test identity", (r) => ({ ...r, stdout: r.stdout.replace(/^(not ok 1 - ).+/m, "$1module-loader") })],
  ["bailout", (r) => ({ ...r, stdout: r.stdout + "Bail out! broken\n" })],
];
for (const [label, damage] of invalid) {
  test(`C2 rejects ${label} in outer run`, () => {
    const failures = [transportTitles[0]];
    assert.throws(() => classifyTransportRun(damage(transport(result([tlsTitle]), failures)), failures), /Invalid C2 evidence/);
  });
  test(`C2 rejects ${label} in TLS child despite outer assertion wrapper`, () => {
    const child = damage(result([tlsTitle], [tlsTitle]));
    assert.throws(() => classifyTransportRun(transport(child, tlsFailure), tlsFailure), /Invalid C2 evidence/);
  });
}
test("C2 requires a unique TLS receipt and matching inner/outer failure", () => {
  const good = transport();
  assert.throws(() => classifyTransportRun({ ...good, stdout: good.stdout.replace(/^# C2_TLS_RESULT .+\n/m, "") }), /TLS receipt/);
  assert.throws(() => classifyTransportRun({ ...good, stdout: good.stdout + childReceipt(result([tlsTitle])) }), /TLS receipt/);
  assert.throws(() => classifyTransportRun(transport(result([tlsTitle]), tlsFailure), tlsFailure), /outer\/inner TLS mismatch/);
  assert.throws(() => classifyTransportRun(transport(result([tlsTitle], [tlsTitle]))), /outer\/inner TLS mismatch/);
  assert.throws(() => classifyTransportRun({ ...good, stdout: good.stdout.replace(/(# C2_TLS_RESULT )\S+/, "$1bm90LWpzb24=") }), /malformed TLS receipt/);
});
test("C2 refuses incomplete or extra mutation failure sets", () => {
  const actual = transportTitles.slice(0, 2);
  const run = transport(result([tlsTitle]), actual);
  assert.throws(() => classifyTransportRun(run, actual.slice(0, 1)), /failing test census/);
  assert.throws(() => classifyTransportRun(run, transportTitles.slice(0, 3)), /failing test census/);
});
test("invalid child evidence throws ordinary Error, never a behavioral AssertionError", () => {
  assert.throws(() => validateTap({ status: 1, stdout: "", stderr: "load failed" }, [tlsTitle]), (error) => error.constructor === Error && error.code !== "ERR_ASSERTION");
});
