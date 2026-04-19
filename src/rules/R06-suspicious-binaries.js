import { SEVERITY } from '../severity.js';

const EXECUTABLE_EXTS = new Set([
  '.sh', '.bash', '.zsh', '.ksh',
  '.py', '.pyc',
  '.rb', '.pl', '.ps1',
  '.js', '.mjs', '.cjs', '.ts',
  '.exe', '.dll', '.so', '.dylib',
  '.bin', '.out', '.jar', '.class',
  '.wasm',
]);
const BINARY_EXTS = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.out', '.pyc', '.class']);

export default {
  id: 'R06',
  ast: 'AST03',
  title: 'Suspicious executable / binary in skill',
  defaultSeverity: SEVERITY.HIGH,
  check(ctx) {
    const findings = [];
    const fm = ctx.frontmatter || {};
    const name = (fm.name || '').toLowerCase();
    const desc = (fm.description || '').toLowerCase();
    const purposeText = name + ' ' + desc;

    // Heuristic: if the skill description is purely documentary (no mention of running/executing/building/scripting),
    // executables are especially suspicious.
    const claimsExec = /\b(run|execute|script|build|compile|install|deploy|test|fetch|generate|cli|tool|agent|automation)\b/i.test(purposeText);

    for (const f of ctx.files) {
      if (!EXECUTABLE_EXTS.has(f.ext)) continue;
      if (f.relPath === 'SKILL.md') continue;
      // Only flag scripts/binaries inside an actual skill directory.
      const role = ctx.roleOf(f);
      if (role !== 'skill-script') continue;

      if (BINARY_EXTS.has(f.ext)) {
        findings.push(mk(f, SEVERITY.HIGH, `Compiled binary in skill (${f.ext})`));
        continue;
      }
      if (!claimsExec) {
        // Downgrade — many legitimate skills bundle scripts without explicitly
        // saying so in the frontmatter. Elevated severity only if combined
        // with other dangerous findings elsewhere.
        findings.push(mk(f, SEVERITY.LOW, `Bundled script ${f.ext} — review contents`));
      } else {
        findings.push(mk(f, SEVERITY.LOW, `Bundled script ${f.ext} — review contents carefully`));
      }
    }

    // Password-protected archive presence (only inside skill dirs)
    for (const f of ctx.files) {
      if (!/\.(zip|7z|rar|tar\.gz|tgz)$/i.test(f.relPath)) continue;
      if (ctx.roleOf(f) !== 'skill-script') continue;
      findings.push(mk(f, SEVERITY.HIGH, 'Archive inside skill — contents opaque to scanner'));
    }

    return findings;
  },
};

function mk(f, severity, message) {
  return {
    ruleId: 'R06',
    ast: 'AST03',
    severity,
    title: 'Suspicious file in skill',
    file: f.relPath,
    evidence: '',
    message,
  };
}
