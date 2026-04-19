import { SEVERITY } from '../severity.js';

const PATTERNS = [
  { re: /\bcurl\s+[^\n|]*\|\s*(?:bash|sh|zsh|ksh|dash)\b/i, sev: SEVERITY.CRITICAL, hint: 'curl | sh — remote code execution' },
  { re: /\bwget\s+[^\n|]*(?:-O\s*-|--output-document=-)[^\n|]*\|\s*(?:bash|sh)\b/i, sev: SEVERITY.CRITICAL, hint: 'wget -O - | sh — remote code execution' },
  { re: /\bcurl\s+[^\n|]*\|\s*source\b/i, sev: SEVERITY.CRITICAL, hint: 'curl | source — remote shell injection' },
  { re: /\beval\s*\$\(\s*(?:curl|wget|echo\s+.+\|\s*base64)/i, sev: SEVERITY.CRITICAL, hint: 'eval of remote or base64-decoded command' },
  { re: /\bbash\s+<\s*\(\s*curl\b/i, sev: SEVERITY.CRITICAL, hint: 'bash <(curl ...) process substitution RCE' },
  { re: /\bpython3?\s+-c\s+['"]\s*(?:import|exec|__import__)/i, sev: SEVERITY.HIGH, hint: 'inline python -c exec' },
  { re: /\bnode\s+-e\s+['"][^'"]*require\(/i, sev: SEVERITY.HIGH, hint: 'inline node -e require' },
  { re: /\bnc\s+(?:-e|-c)\b/i, sev: SEVERITY.CRITICAL, hint: 'netcat reverse-shell flags' },
  { re: /\bbash\s+-i\s+>&\s*\/dev\/tcp\//i, sev: SEVERITY.CRITICAL, hint: 'bash reverse shell via /dev/tcp' },
  { re: /\/dev\/tcp\/\d/i, sev: SEVERITY.CRITICAL, hint: '/dev/tcp reverse shell' },
  { re: /\bchmod\s+[+-]?\s*[0-7]*777\b/, sev: SEVERITY.MEDIUM, hint: 'chmod 777 (permission abuse)' },
];

export default {
  id: 'R03',
  ast: 'AST01',
  title: 'Dangerous shell invocation',
  defaultSeverity: SEVERITY.CRITICAL,
  check(ctx) {
    const findings = [];
    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;
      for (const p of PATTERNS) {
        const m = text.match(p.re);
        if (m) {
          findings.push({
            ruleId: 'R03',
            ast: 'AST01',
            severity: p.sev,
            title: 'Dangerous shell invocation',
            file: f.relPath,
            evidence: (m[0] || '').slice(0, 160),
            message: p.hint,
          });
        }
      }
    }
    return findings;
  },
};
