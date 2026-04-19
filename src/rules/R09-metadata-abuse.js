import YAML from 'yaml';
import { SEVERITY } from '../severity.js';

// Only flag metadata that actively claims Anthropic/official status. Bare
// words like "verified" or "official" appear in unrelated prose (e.g. "run
// tests, verified" / "official docs") and fire too often.
const IMPERSONATION = /\b(?:anthropic[- ]official|anthropic[- ]team|by[- ]anthropic|anthropic[- ]verified|officially[- ]endorsed|verified[- ]by[- ]anthropic)\b/i;
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

    // Find every SKILL.md in the repo — collection-mode repos have one per
    // sub-skill, single-mode has one at root.
    const skills = ctx.files.filter((f) => f.relPath === 'SKILL.md' || f.relPath.endsWith('/SKILL.md'));

    if (skills.length === 0) {
      findings.push({
        ruleId: 'R09',
        ast: 'AST04',
        severity: SEVERITY.MEDIUM,
        title: 'Missing SKILL.md',
        file: '(root)',
        evidence: '',
        message: 'No SKILL.md found — not a skill package',
      });
      return findings;
    }

    if (ctx.mode === 'collection') {
      findings.push({
        ruleId: 'R09',
        ast: 'AST04',
        severity: SEVERITY.LOW,
        title: 'Multi-skill repository',
        file: '(root)',
        evidence: '',
        message: `Skills collection (${skills.length} skills) — each skill also scanned individually below`,
      });
    }

    for (const skill of skills) {
      const text = ctx.readText(skill) || '';
      const fm = parseFrontmatter(text);
      if (!fm.name || typeof fm.name !== 'string') {
        findings.push(mk(skill.relPath, SEVERITY.MEDIUM, 'SKILL.md frontmatter missing `name`'));
      }
      if (!fm.description || typeof fm.description !== 'string') {
        findings.push(mk(skill.relPath, SEVERITY.MEDIUM, 'SKILL.md frontmatter missing `description`'));
      }
      const haystack = `${fm.name || ''} ${fm.description || ''} ${fm.author || ''}`;
      if (IMPERSONATION.test(haystack) && !/anthropic/i.test(String(fm.repository || ''))) {
        findings.push(mk(skill.relPath, SEVERITY.HIGH, 'Skill claims Anthropic/official status in metadata'));
      }
      for (const p of OVERBROAD_TRIGGER) {
        if (p.test(text) || p.test(String(fm.description || ''))) {
          findings.push(mk(skill.relPath, SEVERITY.MEDIUM, 'Overbroad activation trigger (AST04)'));
          break;
        }
      }
    }
    return findings;
  },
};

function parseFrontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const yaml = text.slice(3, end).replace(/^\s*\n/, '');
  try { return YAML.parse(yaml) || {}; } catch { return {}; }
}

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
