import { readFile } from 'node:fs/promises';
import YAML from 'yaml';
import { ALL_RULES } from './rules/index.js';
import { walkFiles } from './fetcher.js';
import { verdict } from './severity.js';
import { detectMode, classify, downgradeForRole, skipForRole, splitMarkdown, scanTextFor, KNOWN_INSTALLER_HOSTS } from './classify.js';

const TEXT_EXTS = new Set([
  '.md', '.markdown', '.txt', '.rst',
  '.json', '.yaml', '.yml', '.toml',
  '.sh', '.bash', '.zsh', '.ksh',
  '.py', '.rb', '.pl', '.ps1',
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.go', '.rs', '.java', '.kt',
  '.c', '.h', '.cpp', '.hpp',
  '.env', '.ini', '.cfg', '.conf',
  '.html', '.xml', '.css', '.svg',
]);

/**
 * Scan a local directory that contains a skill.
 * @param {string} dir
 * @returns {Promise<{findings: Array, files: Array, frontmatter: object, verdict: object}>}
 */
export async function scanDir(dir) {
  const files = await walkFiles(dir);
  const textCache = new Map();

  async function loadText(f) {
    if (textCache.has(f.relPath)) return textCache.get(f.relPath);
    if (f.tooLarge) {
      textCache.set(f.relPath, '');
      return '';
    }
    try {
      const buf = await readFile(f.absPath);
      // Heuristic binary detection: presence of NUL
      if (buf.includes(0)) {
        textCache.set(f.relPath, '');
        return '';
      }
      const text = buf.toString('utf8');
      textCache.set(f.relPath, text);
      return text;
    } catch {
      textCache.set(f.relPath, '');
      return '';
    }
  }

  // Preload text for all textual files in parallel
  await Promise.all(files.filter(isText).map(loadText));

  const { mode, skillRoots } = detectMode(files);

  const skillFile = files.find((f) => f.relPath === 'SKILL.md');
  let frontmatter = {};
  let skillText = '';
  if (skillFile) {
    skillText = textCache.get(skillFile.relPath) || '';
    frontmatter = parseFrontmatter(skillText);
  }

  const roleCache = new Map();
  function roleOf(f) {
    if (!roleCache.has(f.relPath)) {
      roleCache.set(f.relPath, classify(f, mode, skillRoots));
    }
    return roleCache.get(f.relPath);
  }

  const ctx = {
    files,
    frontmatter,
    skillText,
    mode,
    skillRoots,
    knownInstallerHosts: KNOWN_INSTALLER_HOSTS,
    isText,
    readText(f) { return textCache.get(f.relPath) || ''; },
    scanText(f) {
      const t = textCache.get(f.relPath) || '';
      return scanTextFor(f, t, roleOf(f));
    },
    roleOf,
    splitMarkdown,
  };

  const findings = [];
  for (const rule of ALL_RULES) {
    try {
      const res = await rule.check(ctx);
      if (!Array.isArray(res)) continue;
      for (const raw of res) {
        const file = files.find((ff) => ff.relPath === raw.file);
        const role = file ? roleOf(file) : 'other';
        if (skipForRole(role, raw.ruleId)) continue;
        // opts allow a rule to mark a finding as still-meaningful-in-readme
        // (e.g. hardcoded key literal leaks even in docs).
        const sev = downgradeForRole(raw.severity, role, { allowInReadme: raw._allowInReadme });
        if (!sev) continue;
        // strip internal flags before emitting
        const { _allowInReadme, ...rest } = raw;
        findings.push({ ...rest, severity: sev, role });
      }
    } catch (err) {
      findings.push({
        ruleId: rule.id,
        ast: rule.ast,
        severity: 'LOW',
        title: `Rule ${rule.id} errored`,
        file: '(scanner)',
        evidence: '',
        message: err?.message || String(err),
      });
    }
  }

  return {
    files: files.map((f) => ({ relPath: f.relPath, size: f.size, role: roleOf(f) })),
    frontmatter,
    mode,
    skillRoots,
    findings,
    verdict: verdict(findings),
  };
}

function isText(f) {
  if (f.tooLarge) return false;
  if (TEXT_EXTS.has(f.ext)) return true;
  // Files without ext are treated as text if small
  if (f.ext === '' && f.size < 256 * 1024) return true;
  return false;
}

function parseFrontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const yaml = text.slice(3, end).replace(/^\s*\n/, '');
  try {
    return YAML.parse(yaml) || {};
  } catch {
    return {};
  }
}
