import { SEVERITY } from '../severity.js';
import { HOME_PREFIX_RE } from '../classify.js';

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
    // High-value Claude Code persistence paths. Literal path suffix (without
    // home prefix) used for the "any write + any mention" fallback.
    const HV_PATH_SUFFIX = /\.claude\/(?:CLAUDE\.md|settings(?:\.local)?\.json|hooks)|\.ssh\/authorized_keys/i;
    const HIGH_VALUE = new RegExp(
      String.raw`(?:` + HOME_PREFIX_RE + String.raw`)?\/?\.claude\/(?:CLAUDE\.md|settings(?:\.local)?\.json|hooks)|\.ssh\/authorized_keys`,
      'i'
    );
    const ANY_WRITE = /(?:>>|>)\s*["']?\$?\w+|\bfs\.(?:writeFile|appendFile|writeFileSync|appendFileSync)\s*\(|\btee\b[^\n]*(?:>>|>)|\bopen\s*\(\s*[^,]+,\s*["'][aw]/i;
    // Write-to-target patterns — proximity is proven by putting the target
    // and a write operator in the same regex.
    const writeTargetPatterns = [
      /(?:>>|>)\s*["']?(~\/\.(?:claude\/(?:CLAUDE\.md|settings(?:\.local)?\.json|hooks[^\s"']*)|bashrc|zshrc|profile|bash_profile|zprofile|gitconfig|ssh\/(?:authorized_keys|config)))/i,
      /(?:echo|cat|tee|printf)[^\n]{0,120}(?:>>|>)\s*["']?(~\/\.(?:claude|bashrc|zshrc|profile|bash_profile|zprofile|gitconfig|ssh)\b[^\s"']*)/i,
      /fs\.(?:writeFile|appendFile|writeFileSync|appendFileSync)\s*\(\s*["'`][^"'`]*\.(?:claude|bashrc|zshrc|profile|gitconfig|ssh)/i,
      /open\s*\(\s*["'`][^"'`]*(?:\.claude|bashrc|zshrc|profile|gitconfig|ssh)[^"'`]*["'`]\s*,\s*["'][aw]/i,
    ];
    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;
      const scanText = ctx.scanText(f);
      if (!scanText) continue;
      // Variable-indirection (single-hop): `M="$HOME/.claude/CLAUDE.md"` + `>> $M`.
      let criticalEmitted = false;
      {
        const assignRe = new RegExp(String.raw`\b(\w+)\s*=\s*["']?(?:[^"'\n]*?)(?:` + HIGH_VALUE.source + String.raw`)`, 'gi');
        for (const am of scanText.matchAll(assignRe)) {
          const varName = am[1];
          if (!varName) continue;
          const writeVarRe = new RegExp(String.raw`(?:>>|>)\s*["']?\$\{?` + varName + String.raw`\}?`, 'i');
          if (writeVarRe.test(scanText)) {
            findings.push({
              ruleId: 'R07',
              ast: 'AST01',
              severity: SEVERITY.CRITICAL,
              title: 'Persistence / agent-state tamper',
              file: f.relPath,
              evidence: (am[0] || '').slice(0, 160),
              message: `variable ${varName} holds high-value persistence path AND is written to — indirection RCE`,
            });
            criticalEmitted = true;
            break;
          }
        }
      }

      // Multi-hop taint propagation for nested var-indirection:
      //   A=~; B=$A/.claude/CLAUDE.md; echo x >> $B
      // Step 1: mark vars whose RHS contains ~, $HOME, ${HOME...}, or
      //   expands to a high-value path directly.
      // Step 2: propagate — a var whose RHS references an already-tainted var
      //   AND ends in a high-value suffix is itself high-value.
      // Step 3: if any high-value var is written to via >>/>, emit CRITICAL.
      if (!criticalEmitted) {
        const assignLine = /\b(\w+)\s*=\s*["']?([^"'\n;#]+)/g;
        const tainted = new Set(); // vars holding a home expansion
        const hvVars = new Set();  // vars holding a full high-value path
        // Seed: home-expansion assigns
        for (const m of scanText.matchAll(assignLine)) {
          const v = m[1], rhs = m[2];
          if (/(?:^|\s|["'`(])(?:~|\$HOME|\$\{HOME(?:[:\-=+?!#%*][^}]*)?\})(?:\s*$|\/|["'`])/.test(' ' + rhs)) {
            tainted.add(v);
          }
        }
        // Propagate + detect high-value composition (up to 3 hops)
        for (let hop = 0; hop < 3; hop++) {
          for (const m of scanText.matchAll(assignLine)) {
            const v = m[1], rhs = m[2];
            const refsTainted = [...tainted].some((t) => new RegExp(String.raw`\$\{?` + t + String.raw`\}?`).test(rhs));
            const hasHvSuffix = HV_PATH_SUFFIX.test(rhs);
            if ((refsTainted && hasHvSuffix) || (tainted.has(v) && hasHvSuffix) || hasHvSuffix && /(?:\$\{?[A-Za-z_]\w*\}?|~|\$HOME)/.test(rhs)) {
              hvVars.add(v);
            }
            if (refsTainted) tainted.add(v); // propagate taint
          }
        }
        // Emit if any hv var is written to
        for (const v of hvVars) {
          const writeVarRe = new RegExp(String.raw`(?:>>|>)\s*["']?\$\{?` + v + String.raw`\}?`, 'i');
          if (writeVarRe.test(scanText)) {
            findings.push({
              ruleId: 'R07',
              ast: 'AST01',
              severity: SEVERITY.CRITICAL,
              title: 'Persistence / agent-state tamper',
              file: f.relPath,
              evidence: `$${v}`,
              message: `variable ${v} composes a high-value persistence path via indirection AND is written to`,
            });
            criticalEmitted = true;
            break;
          }
        }
      }

      // Split-component heuristic: `DIR=".claude"; FILE="CLAUDE.md"` style
      // assignments suggest deliberate obfuscation. Flag HIGH if the file
      // contains a claude-dir component AND a high-value file component AND
      // any write-to-variable. Below CRITICAL (hard to be certain without
      // taint) but still blocks SAFE verdict.
      if (!criticalEmitted) {
        const claudeComp = /\b\w+\s*=\s*["']\.?claude["']/i;
        const fileComp = /\b\w+\s*=\s*["'](?:CLAUDE\.md|settings(?:\.local)?\.json|hooks|authorized_keys)["']/i;
        const writeToVar = /(?:>>|>)\s*["']?\$\w+/;
        if (claudeComp.test(scanText) && fileComp.test(scanText) && writeToVar.test(scanText)) {
          findings.push({
            ruleId: 'R07',
            ast: 'AST01',
            severity: SEVERITY.HIGH,
            title: 'Persistence / agent-state tamper',
            file: f.relPath,
            evidence: '',
            message: 'split-component path assembly (claude + CLAUDE.md/settings/hooks) with write-to-var — suspicious',
          });
        }
      }
      for (const t of TARGETS) {
        // Use matchAll so we find every occurrence (different mentions may
        // have different proximity to a write op).
        const matches = [...scanText.matchAll(new RegExp(t.re.source, t.re.flags.includes('g') ? t.re.flags : t.re.flags + 'g'))];
        for (const m of matches) {
          const idx = m.index ?? 0;
          // Real proximity: look for a write-to-target operator within ±240
          // chars of the mention — not anywhere in the file.
          const window = scanText.slice(Math.max(0, idx - 240), idx + 240);
          const hasWrite = writeTargetPatterns.some((w) => w.test(window));
          findings.push({
            ruleId: 'R07',
            ast: 'AST01',
            severity: hasWrite ? SEVERITY.CRITICAL : SEVERITY.MEDIUM,
            title: 'Persistence / agent-state tamper',
            file: f.relPath,
            evidence: (m[0] || '').slice(0, 160),
            message: t.hint + (hasWrite ? ' (with write operation targeting it)' : ''),
          });
        }
      }
    }
    return findings;
  },
};
