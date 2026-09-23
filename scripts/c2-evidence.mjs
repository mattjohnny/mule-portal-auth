// Deliberately narrow parser for these flat Node TAP suites. Invalid evidence is
// an Error, never an AssertionError that could be mistaken for a killed mutant.
export const tlsTitle = "HTTPS succeeds; redirects cannot move credentials, bodies or proof trust";
export const transportTitles = [
  "production: all HTTP transport paths reject without sending credentials",
  "Render without NODE_ENV: all HTTP transport paths reject without sending credentials",
  "Render with development NODE_ENV: all HTTP transport paths reject without sending credentials",
  "local HTTP remains usable with NODE_ENV=undefined",
  "local HTTP remains usable with NODE_ENV=development",
  "local HTTP remains usable with NODE_ENV=test",
  "real trusted HTTPS transport and downgrade redirects",
];
export const receiptPrefix = "# C2_TLS_RESULT ";
function requireEvidence(condition, message) {
  if (!condition) throw new Error(`Invalid C2 evidence: ${message}`);
}

export function validateTap(result, titles) {
  requireEvidence(!result.error && !result.signal, "process error, signal or timeout");
  requireEvidence(result.status === 0 || result.status === 1, "abnormal exit");
  requireEvidence(typeof result.stdout === "string" && !result.stderr?.trim(), "missing stdout or unexpected stderr");
  const text = result.stdout.replace(/\r\n/g, "\n");
  requireEvidence(!/^Bail out!/m.test(text), "TAP bailout");
  const one = (pattern, label) => {
    const matches = [...text.matchAll(pattern)];
    requireEvidence(matches.length === 1, `missing/duplicate ${label}`);
    return Number(matches[0][1]);
  };
  requireEvidence(one(/^1\.\.(\d+)$/gm, "plan") === titles.length, "wrong plan");
  const records = [...text.matchAll(/^(ok|not ok) (\d+) - ([^\n]+)\n  ---\n([\s\S]*?)^  \.\.\.$/gm)];
  requireEvidence(records.length === titles.length, "incomplete test records");
  requireEvidence([...text.matchAll(/^(?:ok|not ok) /gm)].length === titles.length, "extra test records");
  const failed = [];
  records.forEach((record, index) => {
    requireEvidence(Number(record[2]) === index + 1 && record[3] === titles[index], "wrong test identity/order or skip directive");
    const diagnostic = record[4];
    requireEvidence(/^  type: 'test'$/m.test(diagnostic), "unexpected test type");
    if (record[1] === "not ok") {
      requireEvidence(/^  failureType: 'testCodeFailure'$/m.test(diagnostic), "cancelled/hook/infrastructure failure");
      requireEvidence(/^  code: 'ERR_ASSERTION'$/m.test(diagnostic) && /^  name: 'AssertionError'$/m.test(diagnostic), "failure is not a behavioral assertion");
      failed.push(record[3]);
    }
  });
  for (const [key, expected] of Object.entries({ tests: titles.length, suites: 0, pass: titles.length - failed.length, fail: failed.length, cancelled: 0, skipped: 0, todo: 0 })) {
    requireEvidence(one(new RegExp(`^# ${key} (\\d+)$`, "gm"), key) === expected, `wrong ${key} census`);
  }
  const duration = one(/^# duration_ms (\d+(?:\.\d+)?)$/gm, "duration");
  requireEvidence(Number.isFinite(duration), "invalid duration");
  requireEvidence(result.status === (failed.length ? 1 : 0), "exit/census mismatch");
  return { failed };
}

export function childReceipt(result) {
  return receiptPrefix + Buffer.from(JSON.stringify({
    status: result.status, signal: result.signal, error: result.error ? String(result.error) : null,
    stdout: result.stdout, stderr: result.stderr,
  })).toString("base64") + "\n";
}

export function classifyTransportRun(result, expectedFailures = []) {
  const outer = validateTap(result, transportTitles);
  const receipts = [...result.stdout.matchAll(/^# C2_TLS_RESULT ([A-Za-z0-9+/=]+)\r?$/gm)];
  requireEvidence(receipts.length === 1, "missing/duplicate TLS receipt");
  let child;
  try { child = JSON.parse(Buffer.from(receipts[0][1], "base64").toString()); }
  catch { throw new Error("Invalid C2 evidence: malformed TLS receipt"); }
  const inner = validateTap(child, [tlsTitle]);
  requireEvidence(outer.failed.includes(transportTitles[6]) === (inner.failed.length === 1), "outer/inner TLS mismatch");
  requireEvidence(JSON.stringify(outer.failed) === JSON.stringify(expectedFailures), "unexpected failing test census");
  return { failed: outer.failed, tlsFailed: inner.failed };
}
