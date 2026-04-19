import { SEVERITY } from '../severity.js';

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

export default {
  id: 'R04',
  ast: 'AST01',
  title: 'Credential exfiltration pattern',
  defaultSeverity: SEVERITY.CRITICAL,
  check(ctx) {
    const findings = [];
    const envRe = new RegExp('\\$\\{?(' + ENV_NAMES.join('|') + ')\\}?', 'g');
    const homeSecretRe = /~\/\.(?:aws|ssh|claude|config\/gcloud)\b/i;
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

    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;

      if (urlWithEnv.test(text)) {
        findings.push(mk(f, SEVERITY.CRITICAL, 'Env var (secret) interpolated into URL — classic exfil'));
      }
      if (curlHeaderEnv.test(text)) {
        findings.push(mk(f, SEVERITY.CRITICAL, 'Env var sent in curl auth header to third-party'));
      }
      if (homeSecretRe.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Reference to user secret directory (~/.aws, ~/.ssh, ~/.claude)'));
      }
      for (const p of hardcodedPatterns) {
        if (p.re.test(text)) {
          findings.push(mk(f, SEVERITY.HIGH, p.hint));
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
