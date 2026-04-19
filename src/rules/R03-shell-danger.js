import { SEVERITY } from '../severity.js';
import { INTERPRETER_RE } from '../classify.js';

const PATTERNS = [
  { re: new RegExp(String.raw`\bcurl\s+[^\n|]*\|\s*` + INTERPRETER_RE + String.raw`\b`, 'i'), sev: SEVERITY.CRITICAL, hint: 'curl | sh — remote code execution' },
  { re: new RegExp(String.raw`\bwget\s+[^\n|]*(?:-O\s*-|--output-document=-)[^\n|]*\|\s*` + INTERPRETER_RE + String.raw`\b`, 'i'), sev: SEVERITY.CRITICAL, hint: 'wget -O - | sh — remote code execution' },
  { re: /\bcurl\s+[^\n|]*\|\s*source\b/i, sev: SEVERITY.CRITICAL, hint: 'curl | source — remote shell injection' },
  { re: /\beval\s*["']?\$\(\s*(?:curl|wget|(?:curl|wget|echo|printf|cat)\b[^|\n]*\|\s*base64)/i, sev: SEVERITY.CRITICAL, hint: 'eval of remote or base64-decoded command' },
  { re: /\bbash\s+<\s*\(\s*curl\b/i, sev: SEVERITY.CRITICAL, hint: 'bash <(curl ...) process substitution RCE' },
  { re: /\bcurl\s+[^\n]*\|\s*tee\s+(?:[^\n]*\s)?>\s*\(\s*(?:bash|sh|zsh|ksh)\b/i, sev: SEVERITY.CRITICAL, hint: 'curl | tee >(bash) — tee-substitution RCE' },
  { re: /\bcurl\s+[^\n]*\|\s*xargs\b[^\n]*\b(?:bash|sh|zsh|ksh|dash|ash)\b/i, sev: SEVERITY.CRITICAL, hint: 'curl | xargs ... sh — RCE' },
  // Download-then-source: curl -o /tmp/x.sh && . /tmp/x.sh
  { re: /\b(?:curl|wget)\s+[^\n]*-(?:o|O)\s+(["']?)(\/?[\w.\/\-]+\.(?:sh|bash|py|pl))\1[^\n]{0,80}?(?:;|&&|\|\||\n)[^\n]{0,80}?(?:\.\s+|\bsource\s+|\bbash\s+|\bsh\s+|\bpython3?\s+)\1?\2\1?/i, sev: SEVERITY.CRITICAL, hint: 'download-then-source / download-then-run' },
  // Download-via-redirect-then-run: curl url > $F; bash $F
  { re: /\b(?:curl|wget)\s+[^\n]*\s>\s*["']?\$\{?(\w+)\}?["']?[^\n]{0,80}?(?:;|&&|\|\||\n)[^\n]{0,80}?\b(?:\.|source|bash|sh|zsh|python3?|node|perl|ruby)\s+["']?\$\{?\1\}?/i, sev: SEVERITY.CRITICAL, hint: 'download-via-redirect-then-run' },
  { re: /\b(?:bash|sh|zsh|ksh)\s+-c\s+["'`]?\$\(\s*curl\b/i, sev: SEVERITY.CRITICAL, hint: 'bash -c "$(curl ...)" — RCE via command substitution' },
  { re: /\beval\s+["'`]?\$\(\s*curl\b/i, sev: SEVERITY.CRITICAL, hint: 'eval "$(curl ...)" — RCE' },
  { re: /\bpython3?\s+-c\s+['"]\s*(?:import|exec|__import__)/i, sev: SEVERITY.HIGH, hint: 'inline python -c exec' },
  { re: /\bnode\s+-e\s+['"][^'"]*require\(/i, sev: SEVERITY.HIGH, hint: 'inline node -e require' },
  { re: /\bnc\s+(?:-e|-c)\b/i, sev: SEVERITY.CRITICAL, hint: 'netcat reverse-shell flags' },
  { re: /\b(?:bash|sh|zsh|ksh|dash|ash)\s+-i\s+>&\s*\/dev\/tcp\//i, sev: SEVERITY.CRITICAL, hint: 'reverse shell via /dev/tcp' },
  { re: /\/dev\/tcp\/[\w.-]+\/\d+/i, sev: SEVERITY.CRITICAL, hint: '/dev/tcp reverse shell (host:port)' },
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

      // For readme/doc markdown, only scan code-fence content (prose in a
      // tutorial isn't agent-executable). For skill files, scan all text.
      const scanText = ctx.scanText(f);
      if (!scanText) continue;

      for (const p of PATTERNS) {
        const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
        for (const m of scanText.matchAll(re)) {
          let sev = p.sev;

          // curl | sh to a CURATED installer host (astral.sh / brew.sh / ...)
          // is a canonical pattern, downgrade to LOW. Hostnames only — path
          // is stripped. Never downgrade for raw user-content hosts.
          if (/curl|wget/.test(p.hint || '')) {
            const urlMatch = m[0].match(/https?:\/\/([a-z0-9.-]+)/i);
            const host = urlMatch ? urlMatch[1].toLowerCase() : '';
            if (host && isInstallerHost(host, ctx.knownInstallerHosts) && sev === 'CRITICAL') {
              sev = 'LOW';
            }
          }

          findings.push({
            ruleId: 'R03',
            ast: 'AST01',
            severity: sev,
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

function isInstallerHost(host, set) {
  for (const h of set) {
    if (host === h || host.endsWith('.' + h)) return true;
  }
  return false;
}
