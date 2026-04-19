import { SEVERITY } from '../severity.js';

// Recursive-force flag variants + optional long-flags like --no-preserve-root
// that attackers interleave to defeat a naive `rm\s+-rf` anchor.
const RMRF = String.raw`\brm\s+(?:(?:-[rRfv]+|(?:-[rRfv]\s+){1,2}|--recursive(?:\s+--force)?|--force\s+--recursive|--no-preserve-root)\s+)+`;
const TERM = String.raw`(?:[\s;|&"'\)\*]|$)`; // any shell terminator, not just space
// Home-dir target forms: ~, ~/, "$HOME", ${HOME}, ${HOME:-/tmp}, '$HOME/' etc.
const HOMEROOT = String.raw`["']?(?:~|\$HOME|\$\{HOME(?:[:\-=+?!#%*][^}]*)?\})\/?["']?`;
// Unbounded ROOT target: / optionally followed by trailing slash or */
const ROOTSLASH = String.raw`["']?\/["']?`;
const PATTERNS = [
  // Unbounded root deletions. Covers: `rm -rf /`, `rm -rf ~`, `rm -rf ~/`,
  // `rm -rf "$HOME"`, `rm -rf ${HOME}`, `rm -rf *`, `rm -rf /*`.
  // `rm -rf ~/.claude/skills/foo` (targeted subdir) is intentionally NOT flagged.
  { re: new RegExp(RMRF + String.raw`(?:` + ROOTSLASH + String.raw`(?:\*|${TERM})|\/\*|${HOMEROOT}${TERM}|\*${TERM})`, 'i'), sev: SEVERITY.CRITICAL, hint: 'rm -rf on root / home / wildcard' },
  { re: new RegExp(String.raw`\bsudo\s+` + RMRF + String.raw`\/`, 'i'), sev: SEVERITY.CRITICAL, hint: 'sudo rm -rf /' },
  // Bounded user-dir deletion — less severe but still notable.
  { re: new RegExp(RMRF + String.raw`(?:~|\$HOME|\$\{HOME(?:[:\-=+?!#%*][^}]*)?\})\/[^\s` + "`" + String.raw`'"]+`, 'i'), sev: SEVERITY.MEDIUM, hint: 'rm -rf on user-dir subpath' },
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
      const scanText = ctx.scanText(f);
      if (!scanText) continue;
      for (const p of PATTERNS) {
        const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
        for (const m of scanText.matchAll(re)) {
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
