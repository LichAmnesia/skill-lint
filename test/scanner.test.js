import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanDir } from '../src/scanner.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (name) => join(here, 'fixtures', name);

test('safe skill → SAFE verdict', async () => {
  const res = await scanDir(fx('safe-skill'));
  assert.equal(res.verdict.label, 'SAFE', `findings: ${JSON.stringify(res.findings, null, 2)}`);
  assert.equal(res.findings.length, 0);
});

test('prompt-injection fixture → TOXIC + R01 + R04', async () => {
  const res = await scanDir(fx('toxic-prompt-injection'));
  assert.equal(res.verdict.label, 'TOXIC');
  const ids = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ids.has('R01'), 'expected R01 prompt-injection');
  assert.ok(ids.has('R03'), 'expected R03 shell-danger (curl | bash)');
  assert.ok(ids.has('R04'), 'expected R04 credential-exfil (ANTHROPIC_API_KEY in URL)');
});

test('base64 fixture → TOXIC + R02 + R03', async () => {
  const res = await scanDir(fx('toxic-base64'));
  assert.equal(res.verdict.label, 'TOXIC');
  const ids = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ids.has('R02'), 'expected R02 obfuscation');
  assert.ok(ids.has('R03'), 'expected R03 (eval $(… base64 -d))');
  assert.ok(ids.has('R04'), 'expected R04 (~/.aws reference)');
});

test('curl-bash fixture → TOXIC + R03 + R07 + R08 + R09 + R10', async () => {
  const res = await scanDir(fx('toxic-curl-bash'));
  assert.equal(res.verdict.label, 'TOXIC');
  const ids = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ids.has('R03'), 'expected R03 dangerous shell');
  assert.ok(ids.has('R07'), 'expected R07 persistence tamper (~/.claude/settings.json)');
  assert.ok(ids.has('R08'), 'expected R08 destructive op (rm -rf / systemctl disable)');
  assert.ok(ids.has('R09'), 'expected R09 metadata abuse (Anthropic official claim)');
  assert.ok(ids.has('R10'), 'expected R10 over-privilege (Bash(*))');
});

test('scoring: verdict exit codes match thresholds', async () => {
  const safe = await scanDir(fx('safe-skill'));
  assert.equal(safe.verdict.exitCode, 0);
  const toxic = await scanDir(fx('toxic-prompt-injection'));
  assert.equal(toxic.verdict.exitCode, 2);
});
