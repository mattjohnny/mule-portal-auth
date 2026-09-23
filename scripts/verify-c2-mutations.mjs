// Run after build, without concurrent builds/tests. Mutates only the emitted
// transport, restores exact bytes in finally, and retains every failed proof.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { classifyTransportRun, transportTitles } from "./c2-evidence.mjs";

const path = "dist/portal.js";
const original = readFileSync(path);
const code = original.toString();
const output = process.argv[2] ?? `docs/evidence/c2-${new Date().toISOString().replace(/[:.]/g, "-")}`;
// Never overwrite an earlier proof run, including an incomplete one.
mkdirSync(output, { recursive: false });
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
function modulePreflight(name) {
  for (const [step, args] of [
    ["syntax", ["--check", path]],
    ["load", ["--input-type=module", "-e", "await import('./dist/portal.js'); await import('./dist/index.js'); console.log('C2_MODULE_LOADED');"]],
  ]) {
    const result = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 10_000 });
    writeFileSync(`${output}/${name}-${step}.txt`, `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trimEnd() + "\n");
    assert.ifError(result.error);
    assert.equal(result.signal, null, `${name} ${step}: signal`);
    assert.equal(result.status, 0, `${name} ${step}: module preflight failed`);
    assert.equal(result.stderr, "", `${name} ${step}: unexpected stderr`);
    if (step === "load") assert.equal(result.stdout.trim(), "C2_MODULE_LOADED");
  }
}
const results = [];
try {
  modulePreflight("preflight");
  classifyTransportRun(run("preflight").result);
  for (const [name, from, to, expected] of mutations) {
    writeFileSync(path, replace(from, to));
    modulePreflight(name);
    const expectedFailures = transportTitles.filter((title) => expected.some((part) => title.includes(part)));
    assert.ok(expectedFailures.length > 0, "nonempty mutation failure expectation");
    const { failed, tlsFailed } = classifyTransportRun(run(name).result, expectedFailures);
    results.push({ name, status: "assertion-killed", modulePreflight: "syntax-and-load-passed", failed, tlsFailed });
    console.log(`${name}: assertion-killed`);
    writeFileSync(path, original);
  }
} finally {
  writeFileSync(path, original);
  assert.deepEqual(readFileSync(path), original, "exact byte restoration");
  writeFileSync(`${output}/mutations.json`, JSON.stringify({ runtime: process.version, artifactSha256: createHash("sha256").update(original).digest("hex"), results }, null, 2) + "\n");
}
modulePreflight("restored");
classifyTransportRun(run("restored").result);
writeFileSync(`${output}/completion.json`, JSON.stringify({
  status: "complete", declaredMutants: mutations.length, assertionKilled: results.length,
  restoredBaseline: "passed", exactByteRestoration: readFileSync(path).equals(original),
  artifactSha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
}, null, 2) + "\n");
console.log(`${results.length}/${mutations.length} killed; exact bytes restored; restored suite passed`);
