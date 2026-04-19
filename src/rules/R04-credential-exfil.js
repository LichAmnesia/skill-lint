import { SEVERITY } from '../severity.js';
import { HOME_PREFIX_RE } from '../classify.js';

const ENV_NAMES = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GEMINI_API_KEY',
  'GOOGLE_API_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'NPM_TOKEN',
  'SLACK_TOKEN',
  'STRIPE_SECRET_KEY',
  'HF_TOKEN',
];

// Canonical provider hostnames for each secret. If the skill reads
// ANTHROPIC_API_KEY and only contacts anthropic.com hosts, that's a
// legitimate API consumer — not an exfil.
const PROVIDER_HOSTS = {
  ANTHROPIC_API_KEY: /\bapi\.anthropic\.com\b|\banthropic\.com\b/i,
  OPENAI_API_KEY:    /\bapi\.openai\.com\b|\bopenai\.com\b/i,
  GEMINI_API_KEY:    /\bgenerativelanguage\.googleapis\.com\b|\bgoogleapis\.com\b|\bgoogle\.com\b/i,
  GOOGLE_API_KEY:    /\bgoogleapis\.com\b|\bgoogle\.com\b/i,
  AWS_ACCESS_KEY_ID:     /\bamazonaws\.com\b|\baws\.amazon\.com\b/i,
  AWS_SECRET_ACCESS_KEY: /\bamazonaws\.com\b|\baws\.amazon\.com\b/i,
  AWS_SESSION_TOKEN:     /\bamazonaws\.com\b|\baws\.amazon\.com\b/i,
  GITHUB_TOKEN:  /\bapi\.github\.com\b|\bgithub\.com\b|\braw\.githubusercontent\.com\b|\buploads\.github\.com\b/i,
  GH_TOKEN:      /\bapi\.github\.com\b|\bgithub\.com\b|\braw\.githubusercontent\.com\b|\buploads\.github\.com\b/i,
  NPM_TOKEN:     /\bregistry\.npmjs\.org\b|\bnpmjs\.com\b/i,
  SLACK_TOKEN:   /\bslack\.com\b/i,
  STRIPE_SECRET_KEY: /\bapi\.stripe\.com\b|\bstripe\.com\b/i,
  HF_TOKEN:      /\bhuggingface\.co\b|\bhf\.co\b/i,
};

export default {
  id: 'R04',
  ast: 'AST01',
  title: 'Credential exfiltration pattern',
  defaultSeverity: SEVERITY.CRITICAL,
  check(ctx) {
    const findings = [];
    const envRe = new RegExp('\\$\\{?(' + ENV_NAMES.join('|') + ')\\}?', 'g');
    // Real credential stores. HOME_PREFIX_RE covers ~, $HOME, ${HOME},
    // ${HOME:-default}, ${HOME:=x}, etc. ~/.claude as a whole is Claude
    // Code config (R07 handles persistence), but credentials/auth/token
    // subpaths hold real OAuth / API secrets.
    const homeSecretRe = new RegExp(
      HOME_PREFIX_RE + String.raw`\/\.(?:aws|ssh|config\/gcloud|kube|docker\/config\.json|netrc|gnupg|password-store|claude\/\.?(?:credentials|auth|token))`,
      'i'
    );
    const curlHeaderEnv = new RegExp(
      'curl[^\\n]*-H[^\\n]*(?:Authorization|Cookie|X-Api-Key)[^\\n]*\\$\\{?(' + ENV_NAMES.join('|') + ')\\}?',
      'i'
    );
    const urlWithEnv = new RegExp(
      'https?://[^\\s\'"`]*\\$\\{?(' + ENV_NAMES.join('|') + ')\\}?',
      'i'
    );
    // Hardcoded API key patterns
    const hardcodedPatterns = [
      { re: /\bsk-ant-[A-Za-z0-9_-]{20,}/, hint: 'Anthropic API key literal' },
      { re: /\bsk-[A-Za-z0-9]{20,}\b/, hint: 'OpenAI-style API key literal' },
      { re: /\bAKIA[0-9A-Z]{16}\b/, hint: 'AWS access key literal' },
      { re: /\bghp_[A-Za-z0-9]{20,}\b/, hint: 'GitHub personal access token literal' },
      { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, hint: 'Private key embedded' },
    ];

    // Python / JS env-var access for known secret names
    const langEnvRe = new RegExp(
      '(?:os\\.environ(?:\\[|\\.get\\()["\']|process\\.env\\.)(' + ENV_NAMES.join('|') + ')',
      'i'
    );
    // HTTP client / shell-out calls (any lang) that might exfil.
    // Includes os.system / subprocess / pycurl — Python scripts that read a
    // secret and shell out to curl are the default exfil shape.
    const httpClientRe = /\b(?:urlopen|requests\.(?:get|post|put)|fetch\s*\(|axios\.(?:get|post|put)|http\.(?:get|request)|urllib\.request|got\s*\(|os\.system\s*\(|os\.popen\s*\(|subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(|pycurl|child_process\.(?:exec|spawn|execSync|spawnSync))/i;

    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;

      if (urlWithEnv.test(text)) {
        findings.push({ ...mk(f, SEVERITY.CRITICAL, 'Env var (secret) interpolated into URL — classic exfil'), _allowInReadme: true });
      }
      if (curlHeaderEnv.test(text)) {
        findings.push({ ...mk(f, SEVERITY.CRITICAL, 'Env var sent in curl auth header to third-party'), _allowInReadme: true });
      }
      for (const hm of text.matchAll(new RegExp(homeSecretRe.source, 'gi'))) {
        findings.push({ ...mk(f, SEVERITY.HIGH, `Reference to user credential path: ${hm[0]}`), evidence: hm[0].slice(0, 160) });
      }
      // Language-level credential exfil: secret env var read AND HTTP client
      // in the same file. Provider-whitelist: if the secret's canonical
      // provider host is the ONLY HTTP target in the file, this is a legit
      // API consumer. Fire only when the file contacts a non-provider host.
      const envMatch = text.match(langEnvRe);
      if (envMatch && httpClientRe.test(text)) {
        const envName = (envMatch[1] || '').toUpperCase();
        const providerRe = PROVIDER_HOSTS[envName];
        // Collect all URL hosts mentioned in the file
        const urlHosts = [...text.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map((m) => m[1].toLowerCase());
        const hasOffProviderHost = providerRe
          ? urlHosts.some((h) => !providerRe.test(h))
          : urlHosts.length > 0;
        const hasNoUrlButShellOut = urlHosts.length === 0 && /\b(?:os\.system|subprocess\.|os\.popen|child_process)\b/i.test(text);
        if (hasOffProviderHost || hasNoUrlButShellOut) {
          findings.push({ ...mk(f, SEVERITY.CRITICAL, `Secret ${envName} read AND HTTP/shell-out to non-provider destination — probable exfil`), _allowInReadme: true });
        }
      }
      for (const p of hardcodedPatterns) {
        if (p.re.test(text)) {
          // Hardcoded key literals leak even when pasted into a README.
          findings.push({ ...mk(f, SEVERITY.HIGH, p.hint), _allowInReadme: true });
        }
      }
      // env var printed to stdout / echoed
      const printEnv = new RegExp(
        '\\b(?:echo|printf|print|console\\.log)\\b[^\\n]*\\$\\{?(' + ENV_NAMES.join('|') + ')\\}?',
        'i'
      );
      if (printEnv.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Secret env var echoed/printed'));
      }
    }
    return findings;
  },
};

function mk(f, severity, message) {
  return {
    ruleId: 'R04',
    ast: 'AST01',
    severity,
    title: 'Credential exfiltration pattern',
    file: f.relPath,
    evidence: '',
    message,
  };
}
