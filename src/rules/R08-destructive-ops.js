import { SEVERITY } from '../severity.js';

const PATTERNS = [
  { re: /\brm\s+-rf?\s+(?:\/|~|\$HOME\b|\*)/i, sev: SEVERITY.CRITICAL, hint: 'rm -rf on root / home / wildcard' },
  { re: /\bsudo\s+rm\s+-rf?\b/i, sev: SEVERITY.CRITICAL, hint: 'sudo rm -rf' },
  { re: /\bmkfs\b|\bdd\s+if=\/dev\/zero/i, sev: SEVERITY.CRITICAL, hint: 'filesystem wipe (mkfs / dd)' },
  { re: /:\(\)\{\s*:\|:&\s*\};:/, sev: SEVERITY.CRITICAL, hint: 'fork bomb' },
  { re: /\bgit\s+reset\s+--hard\b/i, sev: SEVERITY.HIGH, hint: 'destructive git reset --hard' },
  { re: /\bgit\s+push\s+(?:--force|-f)\b/i, sev: SEVERITY.HIGH, hint: 'force push' },
  { re: /\bsystemctl\s+(?:disable|stop|mask)\s+(?:firewalld|ufw|apparmor|selinux|sshd)/i, sev: SEVERITY.CRITICAL, hint: 'disabling security services' },
  { re: /\bsetenforce\s+0\b/i, sev: SEVERITY.CRITICAL, hint: 'SELinux enforcement disabled' },
  { re: /\bufw\s+disable\b/i, sev: SEVERITY.HIGH, hint: 'firewall disabled (ufw)' },
  { re: /\bkillall\s+-9\b|\bpkill\s+-9\b/i, sev: SEVERITY.MEDIUM, hint: 'mass process kill' },
  { re: /\bdrop\s+(?:database|table|schema)\b/i, sev: SEVERITY.HIGH, hint: 'destructive SQL DDL' },
];

export default {
  id: 'R08',
  ast: 'AST03',
  title: 'Destructive system operation',
  defaultSeverity: SEVERITY.HIGH,
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
            ruleId: 'R08',
            ast: 'AST03',
            severity: p.sev,
            title: 'Destructive system operation',
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
