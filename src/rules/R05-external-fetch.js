import { SEVERITY } from '../severity.js';

const TRUSTED_HOSTS = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'api.github.com',
  'registry.npmjs.org',
  'pypi.org',
  'files.pythonhosted.org',
  'docs.anthropic.com',
  'anthropic.com',
  'claude.com',
]);

// Password-protected archive extraction. Require `-P` immediately-adjacent to
// the command (not somewhere ~50 chars later inside docstring prose), and
// preserve case on the short flag so `-p` in prose like "pretty-prints"
// doesn't match.
const PASSWORD_ZIP = /\b(?:unzip|7z|zip)\s+(?:-[A-Za-z]*\s+)*(?:-P\s*\S+|--password[= ]\S+)/;
const DYNAMIC_IMPORT = /\b(?:exec|import|require)\s*\(\s*(?:await\s+)?(?:fetch|axios|got|urllib|urllib2|requests)\b/i;

export default {
  id: 'R05',
  ast: 'AST02',
  title: 'Runtime external fetch / supply-chain risk',
  defaultSeverity: SEVERITY.HIGH,
  check(ctx) {
    const findings = [];
    const urlRe = /https?:\/\/([a-z0-9.-]+)(?:\:\d+)?\/[^\s'"`)]*/gi;

    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;

      if (PASSWORD_ZIP.test(text)) {
        findings.push(mk(f, SEVERITY.CRITICAL, 'Password-protected archive extraction (scanner evasion)'));
      }
      if (DYNAMIC_IMPORT.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Dynamic import/exec of fetched content'));
      }

      // URL scanning — only applies to scripts and SKILL.md (not arbitrary docs)
      if (!/\.(md|sh|bash|zsh|py|js|ts|mjs|cjs|rb|pl|ps1)$/i.test(f.relPath)) continue;

      const scanText = ctx.scanText(f);
      if (!scanText) continue;

      let m;
      // Dedupe by full URL (host+path), not host alone — multiple endpoints
      // on the same attacker host should each register.
      const seenUrls = new Set();
      const seenIpHost = new Set();
      while ((m = urlRe.exec(scanText)) !== null) {
        const host = (m[1] || '').toLowerCase();
        const full = m[0];
        if (!host) continue;
        // IP-literal hosts: one finding per host is sufficient signal.
        if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
          if (seenIpHost.has(host)) continue;
          seenIpHost.add(host);
          findings.push(mk(f, SEVERITY.HIGH, `URL uses raw IP literal (${host})`));
          continue;
        }
        if (isInstaller(host, ctx.knownInstallerHosts)) continue;
        if (isTrusted(host)) continue;
        if (seenUrls.has(full)) continue;
        seenUrls.add(full);
        // Only flag when the URL is used for code fetch / install
        const nearby = scanText.slice(Math.max(0, m.index - 40), m.index + 200);
        if (/\b(curl|wget|fetch|pip install|npm install|git clone|source)\b/i.test(nearby)) {
          findings.push(mk(f, SEVERITY.MEDIUM, `Runtime fetch from untrusted host: ${host}`));
        }
      }
    }
    return findings;
  },
};

function isTrusted(host) {
  if (TRUSTED_HOSTS.has(host)) return true;
  for (const t of TRUSTED_HOSTS) {
    if (host === t || host.endsWith('.' + t)) return true;
  }
  return false;
}

function isInstaller(host, set) {
  for (const h of set) {
    if (host === h || host.endsWith('.' + h)) return true;
  }
  return false;
}

function mk(f, severity, message) {
  return {
    ruleId: 'R05',
    ast: 'AST02',
    severity,
    title: 'Runtime external fetch',
    file: f.relPath,
    evidence: '',
    message,
  };
}
