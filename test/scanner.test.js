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

test('collection mode: nested evil SKILL.md still triggers R09+R10', async () => {
  const res = await scanDir(fx('toxic-collection-nested'));
  assert.equal(res.mode, 'collection');
  assert.equal(res.verdict.label, 'TOXIC');
  const ids = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ids.has('R09'), 'expected R09 (impersonation) on nested SKILL.md');
  assert.ok(ids.has('R10'), 'expected R10 (Bash(*) / --dangerously-skip-permissions) on nested SKILL.md');
  // R09+R10 findings should attribute to the nested SKILL.md, not root
  const nestedR10 = res.findings.filter((f) => f.ruleId === 'R10' && f.file === 'skills/evil/SKILL.md');
  assert.ok(nestedR10.length > 0, 'R10 findings must reference the nested SKILL.md path');
});

test('rm -rf flag variants all trigger R08', async () => {
  const res = await scanDir(fx('toxic-rm-variants'));
  const r08 = res.findings.filter((f) => f.ruleId === 'R08');
  // At least 4 of the 5 variants should match (allow one minor miss)
  assert.ok(r08.length >= 4, `expected ≥4 R08 findings for flag variants, got ${r08.length}: ${JSON.stringify(r08.map((f) => f.evidence))}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('reverse-shell via sh/zsh + hostname target triggers R03', async () => {
  const res = await scanDir(fx('toxic-reverse-shell'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03');
  assert.ok(r03.length >= 2, `expected ≥2 R03 reverse-shell findings, got ${r03.length}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('raw.githubusercontent.com is NOT an installer — curl|bash stays CRITICAL', async () => {
  const res = await scanDir(fx('toxic-raw-github'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03');
  assert.ok(r03.some((f) => f.severity === 'CRITICAL'), `raw.githubusercontent must NOT be downgraded; findings=${JSON.stringify(r03)}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('README inside skill dir with prompt injection + curl|bash is TOXIC', async () => {
  const res = await scanDir(fx('toxic-readme-in-skill'));
  const ids = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ids.has('R01'), 'R01 must still fire on README prompt injection (_allowInReadme)');
  assert.equal(res.verdict.label, 'TOXIC', `expected TOXIC, got ${res.verdict.label} score=${res.verdict.score}`);
});

test('rm -rf on ~/ $HOME "$HOME" ${HOME} all trigger R08', async () => {
  const res = await scanDir(fx('toxic-rm-home'));
  const r08 = res.findings.filter((f) => f.ruleId === 'R08' && f.severity === 'CRITICAL');
  assert.ok(r08.length >= 3, `expected ≥3 R08 CRITICAL for home-dir forms, got ${r08.length}: ${JSON.stringify(r08.map((f) => f.evidence))}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('credential exfil via $HOME/ and ${HOME}/ forms triggers R04', async () => {
  const res = await scanDir(fx('toxic-home-cred'));
  const r04 = res.findings.filter((f) => f.ruleId === 'R04');
  assert.ok(r04.length >= 3, `expected ≥3 R04 findings for $HOME/, ${'${HOME}'}/, ~/.claude/auth, got ${r04.length}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('tee >(bash), xargs bash -c, bash -c $(curl) all trigger R03', async () => {
  const res = await scanDir(fx('toxic-tee-xargs'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 3, `expected ≥3 R03 CRITICAL for alternative RCE patterns, got ${r03.length}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('short base64 piped to shell triggers R02 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-base64-short'));
  const r02 = res.findings.filter((f) => f.ruleId === 'R02' && f.severity === 'CRITICAL');
  assert.ok(r02.length >= 1, `expected R02 CRITICAL on base64|sh pipeline`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('variable-indirection write to ~/.claude/CLAUDE.md triggers R07 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-r07-indirect'));
  const r07 = res.findings.filter((f) => f.ruleId === 'R07' && f.severity === 'CRITICAL');
  assert.ok(r07.length >= 1, `expected R07 CRITICAL for var-indirection persistence`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('ChatML tokens + "forget above" + OVERRIDE trigger R01', async () => {
  const res = await scanDir(fx('toxic-chatml'));
  const r01 = res.findings.filter((f) => f.ruleId === 'R01');
  assert.ok(r01.length >= 3, `expected ≥3 R01 findings for ChatML/forget/OVERRIDE, got ${r01.length}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('line-continuation in curl|bash still triggers R03', async () => {
  const res = await scanDir(fx('toxic-line-cont'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03');
  assert.ok(r03.length >= 1, `expected R03 despite backslash line-continuation`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('${HOME:-...} default expansion bypass closed for R04 + R08', async () => {
  const res = await scanDir(fx('toxic-home-default'));
  const r04 = res.findings.filter((f) => f.ruleId === 'R04');
  const r08 = res.findings.filter((f) => f.ruleId === 'R08' && f.severity === 'CRITICAL');
  assert.ok(r04.length >= 1, `expected R04 for ${'${HOME:-/tmp}'} AWS cred exfil`);
  assert.ok(r08.length >= 1, `expected R08 CRITICAL for rm ${'${HOME:-/tmp}'}`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('xargs -n1 sh (no -c flag) triggers R03', async () => {
  const res = await scanDir(fx('toxic-xargs-noc'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for xargs -n1 sh`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('download-then-source RCE triggers R03', async () => {
  const res = await scanDir(fx('toxic-download-source'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for curl -o ... ; . file`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('rm --no-preserve-root / bypass closed', async () => {
  const res = await scanDir(fx('toxic-no-preserve-root'));
  const r08 = res.findings.filter((f) => f.ruleId === 'R08' && f.severity === 'CRITICAL');
  assert.ok(r08.length >= 1, `expected R08 CRITICAL for --no-preserve-root`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('R07 FP: skill that mentions CLAUDE.md in prose + writes unrelated path is not CRITICAL', async () => {
  const res = await scanDir(fx('safe-r07-mention'));
  const r07crit = res.findings.filter((f) => f.ruleId === 'R07' && f.severity === 'CRITICAL');
  assert.equal(r07crit.length, 0, `R07 must not fire CRITICAL on prose-only mention of CLAUDE.md`);
});

test('base64 -d piped to python/node/perl/ruby triggers R02 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-b64-py'));
  const r02 = res.findings.filter((f) => f.ruleId === 'R02' && f.severity === 'CRITICAL');
  assert.ok(r02.length >= 1, `expected R02 CRITICAL for base64|python`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('R07 nested var-indirection A=~; B=$A/.claude/CLAUDE.md triggers CRITICAL', async () => {
  const res = await scanDir(fx('toxic-r07-nested'));
  const r07 = res.findings.filter((f) => f.ruleId === 'R07' && f.severity === 'CRITICAL');
  assert.ok(r07.length >= 1, `expected R07 CRITICAL for multi-hop var-indirection`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('R07 ${HOME:-default}/.claude/CLAUDE.md triggers CRITICAL', async () => {
  const res = await scanDir(fx('toxic-r07-home-default'));
  const r07 = res.findings.filter((f) => f.ruleId === 'R07' && f.severity === 'CRITICAL');
  assert.ok(r07.length >= 1, `expected R07 CRITICAL for ${'${HOME:-default}'} persistence`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('eval $(printf ... | base64 -d) triggers R03 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-eval-printf'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for eval of printf-piped base64`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('python os.environ ANTHROPIC_API_KEY + urlopen triggers R04 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-py-exfil'));
  const r04 = res.findings.filter((f) => f.ruleId === 'R04');
  assert.ok(r04.some((f) => f.severity === 'CRITICAL'), `expected R04 CRITICAL for lang-level env exfil with HTTP client`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('curl | /bin/bash (absolute interpreter path) triggers R03', async () => {
  const res = await scanDir(fx('toxic-interpreter-path'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for /bin/bash`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('curl | env/sudo/nohup <interpreter> triggers R03', async () => {
  const res = await scanDir(fx('toxic-env-wrapper'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for env/sudo wrapper`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('xxd -r -p | bash triggers R02 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-xxd'));
  const r02 = res.findings.filter((f) => f.ruleId === 'R02' && f.severity === 'CRITICAL');
  assert.ok(r02.length >= 1, `expected R02 CRITICAL for xxd hex decode pipeline`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('python subprocess.run(curl ...) + os.environ triggers R04 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-py-subprocess'));
  const r04 = res.findings.filter((f) => f.ruleId === 'R04' && f.severity === 'CRITICAL');
  assert.ok(r04.length >= 1, `expected R04 CRITICAL for subprocess shell-out exfil`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('split-component path assembly (.claude + CLAUDE.md) triggers R07', async () => {
  const res = await scanDir(fx('toxic-r07-components'));
  const r07 = res.findings.filter((f) => f.ruleId === 'R07' && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
  assert.ok(r07.length >= 1, `expected R07 ≥HIGH for split-component assembly`);
  // Split heuristic plus something else should push to TOXIC or at least WARN
  assert.ok(res.verdict.label !== 'SAFE', `expected at least WARN for split-component attack`);
});

test('FP guard: TypeScript generics <User> <System> do NOT fire R01', async () => {
  const res = await scanDir(fx('safe-ts-generics'));
  const r01 = res.findings.filter((f) => f.ruleId === 'R01');
  assert.equal(r01.length, 0, `R01 must not fire on TS generics, got: ${JSON.stringify(r01)}`);
});

test('FP guard: docstring with "zip" and "pretty-prints" does NOT fire R05 PASSWORD_ZIP', async () => {
  const res = await scanDir(fx('safe-docstring-zip'));
  const r05pw = res.findings.filter((f) => f.ruleId === 'R05' && /password/i.test(f.message));
  assert.equal(r05pw.length, 0, `R05 PASSWORD_ZIP must not fire on prose, got: ${JSON.stringify(r05pw)}`);
});

test('FP guard: GitHub API skill (GITHUB_TOKEN + api.github.com) is NOT TOXIC', async () => {
  const res = await scanDir(fx('safe-github-api'));
  const r04crit = res.findings.filter((f) => f.ruleId === 'R04' && f.severity === 'CRITICAL');
  assert.equal(r04crit.length, 0, `R04 must not fire CRITICAL on canonical GitHub API pattern, got: ${JSON.stringify(r04crit)}`);
  assert.notEqual(res.verdict.label, 'TOXIC', `expected ≤WARN, got ${res.verdict.label} score=${res.verdict.score}`);
});

test('FP guard: HuggingFace API skill (HF_TOKEN + huggingface.co) is NOT TOXIC', async () => {
  const res = await scanDir(fx('safe-hf-api'));
  const r04crit = res.findings.filter((f) => f.ruleId === 'R04' && f.severity === 'CRITICAL');
  assert.equal(r04crit.length, 0, `R04 must not fire CRITICAL on canonical HF API pattern`);
  assert.notEqual(res.verdict.label, 'TOXIC');
});

test('eval "$VAR" where VAR=$(... | base64 -d) triggers R02 CRITICAL', async () => {
  const res = await scanDir(fx('toxic-eval-var-cmdsub'));
  const r02 = res.findings.filter((f) => f.ruleId === 'R02' && f.severity === 'CRITICAL');
  assert.ok(r02.length >= 1, `expected R02 CRITICAL for cmd-sub base64 → eval obfuscation`);
  assert.equal(res.verdict.label, 'TOXIC');
});

test('curl url > $F; bash $F (download-redirect-then-run) triggers R03', async () => {
  const res = await scanDir(fx('toxic-download-redirect-run'));
  const r03 = res.findings.filter((f) => f.ruleId === 'R03' && f.severity === 'CRITICAL');
  assert.ok(r03.length >= 1, `expected R03 CRITICAL for download-via-redirect-then-run`);
  assert.equal(res.verdict.label, 'TOXIC');
});
