import { SEVERITY } from '../severity.js';

const TARGETS = [
  { re: /~\/\.claude\/CLAUDE\.md|\$HOME\/\.claude\/CLAUDE\.md/i, hint: 'writes to global CLAUDE.md' },
  { re: /~\/\.claude\/settings(?:\.local)?\.json/i, hint: 'writes to ~/.claude/settings.json (permissions escalation)' },
  { re: /~\/\.claude\/hooks|hooks?\.json/i, hint: 'installs Claude Code hooks' },
  { re: /MEMORY\.md|SOUL\.md/i, hint: 'tampers with agent memory files' },
  { re: /~\/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)/i, hint: 'modifies shell rc (persistence)' },
  { re: /\bcrontab\b|\b(?:launchctl|systemctl)\s+(?:load|enable|start)\b/i, hint: 'installs cron/launchd/systemd persistence' },
  { re: /\.ssh\/authorized_keys/i, hint: 'writes to authorized_keys (SSH backdoor)' },
  { re: /\.ssh\/config/i, hint: 'modifies SSH config' },
  { re: /~\/\.gitconfig/i, hint: 'modifies global git config' },
];

export default {
  id: 'R07',
  ast: 'AST01',
  title: 'Persistence / agent-state tampering',
  defaultSeverity: SEVERITY.HIGH,
  check(ctx) {
    const findings = [];
    const writeContexts = [
      /\b(?:>>|>)\s*/, // shell redirect
      /\b(?:echo|cat|tee|printf)\b[^\n]*(?:>>|>)\s*/,
      /\bfs\.(?:writeFile|appendFile|writeFileSync|appendFileSync)\s*\(/,
      /\bopen\s*\(\s*[^,]+,\s*['"][aw]/, // python open(path, 'w'|'a')
      /\bshutil\.copy/,
    ];
    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;
      for (const t of TARGETS) {
        if (!t.re.test(text)) continue;
        // higher confidence if there's also a write operation
        const hasWrite = writeContexts.some((w) => w.test(text));
        findings.push({
          ruleId: 'R07',
          ast: 'AST01',
          severity: hasWrite ? SEVERITY.CRITICAL : SEVERITY.HIGH,
          title: 'Persistence / agent-state tamper',
          file: f.relPath,
          evidence: '',
          message: t.hint + (hasWrite ? ' (with write operation nearby)' : ''),
        });
      }
    }
    return findings;
  },
};
