import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
const root = 'E:/Code/audit-work/accountability-go-20260922/portal-auth';
const scratch = 'E:/Code/audit-work/accountability-go-20260922/temp/c2-classifier-r3';
const evidence = root + '/docs/evidence/c2-2026-09-22-harness-r3';
mkdirSync(scratch + '/scripts', { recursive: true });
mkdirSync(scratch + '/test', { recursive: true });
copyFileSync(root + '/test/c2-evidence.test.js', scratch + '/test/c2-evidence.test.mjs');
const original = readFileSync(root + '/scripts/c2-evidence.mjs', 'utf8');
const cases = [
 ['ignore-process-errors', 'requireEvidence(!result.error && !result.signal, "process error, signal or timeout");', ''],
 ['ignore-summary-counts', '=== expected, `wrong ${key} census`', '!== -999, `wrong ${key} census`'],
 ['ignore-assertion-kind', 'requireEvidence(/^  code:', 'requireEvidence(true || /^  code:'],
 ['ignore-child-evidence', 'const inner = validateTap(child, [tlsTitle]);', 'const inner = { failed: outer.failed.includes(transportTitles[6]) ? [tlsTitle] : [] };'],
];
const results = [];
try {
 for (const [name, from, to] of cases) {
  assert.equal(original.split(from).length, 2);
  writeFileSync(scratch + '/scripts/c2-evidence.mjs', original.replace(from, to));
  const run = spawnSync(process.execPath, ['--test', 'test/c2-evidence.test.mjs'], { cwd: scratch, encoding: 'utf8', timeout: 10000 });
  assert.ifError(run.error);
  assert.equal(run.status, 1);
  assert.match(run.stdout, /ERR_ASSERTION/);
  assert.match(run.stdout, /# tests 50\r?\n/);
  assert.match(run.stdout, /# cancelled 0\r?\n/);
  const failed = [...run.stdout.matchAll(/^not ok \d+ - (.+)$/gm)].map(m => m[1]);
  writeFileSync(evidence + '/classifier-' + name + '.txt', (run.stdout + '\n' + run.stderr).replace(/[\t ]+$/gm, '').trimEnd() + '\n');
  results.push({ name, status: 'assertion-killed', failed });
 }
} finally {
 writeFileSync(scratch + '/scripts/c2-evidence.mjs', original);
 writeFileSync(evidence + '/classifier-mutations.json', JSON.stringify(results, null, 2) + '\n');
}
console.log(JSON.stringify(results));
