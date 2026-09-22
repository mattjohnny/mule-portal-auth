// Run after build, without concurrent builds/tests. Mutates only the emitted
// transport, restores exact bytes in finally, and retains every failed proof.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const path = "dist/portal.js";
const original = readFileSync(path);
const code = original.toString();
const output = process.argv[2] ?? "docs/evidence/c2-2026-09-22";
mkdirSync(output, { recursive: true });
const replace = (from, to) => {
  assert.equal(code.split(from).length - 1, 1, `unique mutation anchor: ${from}`);
  return code.replace(from, to);
};
const mutations = [
  ["production-guard", 'process.env.NODE_ENV === "production" || process.env.RENDER', 'false || process.env.RENDER', ["production: all HTTP"]],
  ["render-guard", 'process.env.NODE_ENV === "production" || process.env.RENDER', 'process.env.NODE_ENV === "production" || false', ["Render without NODE_ENV", "Render with development NODE_ENV"]],
  ["development-compatibility", '(process.env.NODE_ENV === "production" || process.env.RENDER)', 'true', ["local HTTP remains usable"]],
  ["direct-request-guard", 'portalEndpoint(endpoint, "");', '// guard removed', ["all HTTP transport paths"]],
  ["proof-url-guard", 'portalEndpoint(this.portalUrl, "/api/credential-proof").toString()', '`${this.portalUrl}/api/credential-proof`', ["all HTTP transport paths"]],
  ["credential-redirect", 'return { ...init, headers, redirect: "manual" };\n    }\n    withLegacy', 'return { ...init, headers, redirect: "follow" };\n    }\n    withLegacy', ["real trusted HTTPS"]],
  ["legacy-redirect", 'return { ...init, headers, redirect: "manual" };\n    }\n    async proveCredentials', 'return { ...init, headers, redirect: "follow" };\n    }\n    async proveCredentials', ["real trusted HTTPS"]],
  ["proof-redirect", 'this.withCredential({ method: "POST", signal }, credential)', '{ ...this.withCredential({ method: "POST", signal }, credential), redirect: "follow" }', ["real trusted HTTPS"]],
  ["outage-classification", 'new PortalError("Portal URL must use HTTPS in production or on Render.")', 'new PortalError("Portal URL must use HTTPS in production or on Render.", false, true)', ["all HTTP transport paths"]],
];
function run(name) {
  const result = spawnSync(process.execPath, ["--test", "test/portal-transport.test.js"], { encoding: "utf8", timeout: 45_000 });
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  writeFileSync(`${output}/${name}.txt`, text.replace(/[\t ]+$/gm, "").trimEnd() + "\n");
  assert.ifError(result.error);
  return { result, text };
}
const results = [];
try {
  assert.equal(run("preflight").result.status, 0, "unmodified preflight");
  for (const [name, from, to, expected] of mutations) {
    writeFileSync(path, replace(from, to));
    const { result, text } = run(name);
    const failed = [...text.matchAll(/^not ok \d+ - (.+)$/gm)].map((match) => match[1]);
    assert.equal(result.status, 1, `${name}: must fail normally`);
    assert.match(text, /ERR_ASSERTION/, `${name}: assertion evidence required`);
    assert.ok(failed.length > 0 && failed.every((title) => expected.some((part) => title.includes(part))), `${name}: unexpected failure ${failed}`);
    results.push({ name, status: "assertion-killed", failed });
    console.log(`${name}: assertion-killed`);
    writeFileSync(path, original);
  }
} finally {
  writeFileSync(path, original);
  assert.deepEqual(readFileSync(path), original, "exact byte restoration");
  writeFileSync(`${output}/mutations.json`, JSON.stringify({ runtime: process.version, artifactSha256: createHash("sha256").update(original).digest("hex"), results }, null, 2) + "\n");
}
assert.equal(run("restored").result.status, 0, "restored baseline");
console.log(`${results.length}/${mutations.length} killed; exact bytes restored; restored suite passed`);
