import YAML from 'yaml';
import { SEVERITY } from '../severity.js';

export default {
  id: 'R10',
  ast: 'AST03',
  title: 'Over-privileged permissions',
  defaultSeverity: SEVERITY.MEDIUM,
  check(ctx) {
    const findings = [];

    // Run R10 against every SKILL.md, not just the root one.
    const skills = ctx.files.filter((f) => f.relPath === 'SKILL.md' || f.relPath.endsWith('/SKILL.md'));

    // Body-text permission asks
    const bodyFlags = [
      { re: /\brun (?:any|arbitrary) (?:shell|bash|command)\b/i, sev: SEVERITY.HIGH, hint: 'asks to run arbitrary commands' },
      { re: /\bdisable (?:permission|confirmation) prompts?\b/i, sev: SEVERITY.HIGH, hint: 'asks to disable permission prompts' },
      { re: /\b--dangerously-skip-permissions\b/i, sev: SEVERITY.CRITICAL, hint: 'invokes --dangerously-skip-permissions' },
      { re: /\bsudo\b/, sev: SEVERITY.MEDIUM, hint: 'requests sudo' },
    ];

    for (const skill of skills) {
      const text = ctx.readText(skill) || '';
      const fm = parseFrontmatter(text);

      const allowTools = fm['allowed-tools'] || fm.allowedTools || fm.allow || [];
      const list = Array.isArray(allowTools) ? allowTools : [allowTools].filter(Boolean);
      for (const item of list) {
        const s = String(item);
        if (/^Bash\(\*\)$/.test(s) || /^Bash\s*$/.test(s)) {
          findings.push(mk(skill.relPath, SEVERITY.HIGH, 'Frontmatter grants unrestricted Bash(*)'));
        }
        if (/^Write\(\*\)$/.test(s) || /^Edit\(\*\)$/.test(s)) {
          findings.push(mk(skill.relPath, SEVERITY.MEDIUM, `Frontmatter grants unrestricted ${s}`));
        }
      }

      for (const p of bodyFlags) {
        if (p.re.test(text)) {
          findings.push(mk(skill.relPath, p.sev, p.hint));
        }
      }
    }

    return findings;
  },
};

function parseFrontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const yaml = text.slice(3, end).replace(/^\s*\n/, '');
  try { return YAML.parse(yaml) || {}; } catch { return {}; }
}

function mk(file, severity, message) {
  return {
    ruleId: 'R10',
    ast: 'AST03',
    severity,
    title: 'Over-privileged permissions',
    file,
    evidence: '',
    message,
  };
}
