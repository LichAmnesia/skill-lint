import { SEVERITY } from '../severity.js';

const PATTERNS = [
  { re: /ignore (?:all |the )?(?:previous|prior|above|preceding) (?:instructions?|prompts?|rules?|context)/i, hint: 'classic "ignore previous instructions" override' },
  { re: /\byou are (?:now )?in (?:developer|dev|debug|admin|god|dan|jailbreak) mode\b/i, hint: 'fake mode-switch instruction' },
  { re: /\bdisregard (?:the )?(?:system|safety|security) (?:prompt|message|warnings?)/i, hint: 'safety-bypass instruction' },
  { re: /\b(?:security|safety) (?:warnings?|checks?) (?:are|is) (?:test artifacts?|irrelevant|ignored|disabled)/i, hint: 'safety-disablement framing' },
  { re: /\bpretend (?:to be|you are) (?:an? )?(?:unrestricted|uncensored|jailbroken)/i, hint: 'persona jailbreak' },
  { re: /\bDAN\b|\bdo anything now\b/i, hint: 'DAN-style jailbreak token' },
  { re: /\bdo not (?:tell|inform|notify|alert) (?:the )?user\b/i, hint: 'conceal-from-user instruction' },
  { re: /<\s*\/?\s*(?:system|assistant|user)\s*>/i, hint: 'fake chat-role tag (role impersonation)' },
  { re: /\[\s*INST\s*\]|\[\s*\/\s*INST\s*\]/i, hint: 'Llama-style [INST] injection tokens' },
  { re: /\bact as (?:the )?(?:system|root|admin)\b/i, hint: 'privilege escalation framing' },
];

export default {
  id: 'R01',
  ast: 'AST01',
  title: 'Prompt injection pattern in skill text',
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
            ruleId: 'R01',
            ast: 'AST01',
            severity: SEVERITY.CRITICAL,
            title: 'Prompt injection pattern',
            file: f.relPath,
            evidence: snippet(text, m.index ?? 0),
            message: p.hint,
          });
        }
      }
    }
    return findings;
  },
};

function snippet(text, idx) {
  const start = Math.max(0, idx - 40);
  const end = Math.min(text.length, idx + 120);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}
