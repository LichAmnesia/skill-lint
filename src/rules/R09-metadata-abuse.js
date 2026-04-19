import { SEVERITY } from '../severity.js';

const IMPERSONATION = /\b(?:official|verified|anthropic[- ]official|by anthropic|anthropic team)\b/i;
const OVERBROAD_TRIGGER = [
  /\bwhen(?:ever)? the user (?:asks|types|says) (?:anything|any|a|the)\b/i,
  /\bon (?:every|each|any) (?:message|request|prompt|tool call)\b/i,
  /\balways activate\b/i,
  /\bauto[- ]?trigger\b.*\ball\b/i,
];

export default {
  id: 'R09',
  ast: 'AST04',
  title: 'Metadata abuse / impersonation / overbroad trigger',
  defaultSeverity: SEVERITY.MEDIUM,
  check(ctx) {
    const findings = [];
    const skill = ctx.files.find((f) => f.relPath === 'SKILL.md');
    if (!skill) {
      findings.push({
        ruleId: 'R09',
        ast: 'AST04',
        severity: SEVERITY.MEDIUM,
        title: 'Missing SKILL.md',
        file: '(root)',
        evidence: '',
        message: 'No SKILL.md found at root — not a valid skill package',
      });
      return findings;
    }
    const fm = ctx.frontmatter || {};
    if (!fm.name || typeof fm.name !== 'string') {
      findings.push(mk('SKILL.md', SEVERITY.MEDIUM, 'SKILL.md frontmatter missing `name`'));
    }
    if (!fm.description || typeof fm.description !== 'string') {
      findings.push(mk('SKILL.md', SEVERITY.MEDIUM, 'SKILL.md frontmatter missing `description`'));
    }
    const haystack = `${fm.name || ''} ${fm.description || ''} ${fm.author || ''}`;
    const text = ctx.readText(skill) || '';
    if (IMPERSONATION.test(haystack) && !/anthropic/i.test(String(fm.repository || ''))) {
      findings.push(mk('SKILL.md', SEVERITY.HIGH, 'Skill claims Anthropic/official status in metadata'));
    }
    for (const p of OVERBROAD_TRIGGER) {
      if (p.test(text) || p.test(String(fm.description || ''))) {
        findings.push(mk('SKILL.md', SEVERITY.MEDIUM, 'Overbroad activation trigger (AST04)'));
        break;
      }
    }
    return findings;
  },
};

function mk(file, severity, message) {
  return {
    ruleId: 'R09',
    ast: 'AST04',
    severity,
    title: 'Metadata abuse',
    file,
    evidence: '',
    message,
  };
}
