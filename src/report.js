import chalk from 'chalk';
import { SCORE } from './severity.js';

const SEV_COLOR = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow.bold,
  LOW: chalk.gray,
};

export function printHumanReport(origin, result, opts = {}) {
  const { findings, verdict, frontmatter, files } = result;
  const v = verdict;

  console.log();
  console.log(chalk.bold('skill-lint') + chalk.gray(' — AST10 + Snyk ToxicSkills linter'));
  console.log(chalk.gray('target: ') + origin);
  if (frontmatter?.name) console.log(chalk.gray('skill:  ') + chalk.cyan(frontmatter.name));
  if (frontmatter?.description) {
    console.log(chalk.gray('desc:   ') + truncate(String(frontmatter.description), 200));
  }
  console.log(chalk.gray('files:  ') + files.length);
  console.log();

  if (findings.length === 0) {
    console.log(chalk.green.bold('✔  No findings. 0 risk signals detected.'));
  } else {
    // Group by rule
    const groups = new Map();
    for (const f of findings) {
      const k = f.ruleId;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    for (const [rid, list] of [...groups.entries()].sort()) {
      const first = list[0];
      console.log(
        chalk.bold(`${rid} · ${first.ast} · ${first.title}`) +
        chalk.gray(` (${list.length} finding${list.length > 1 ? 's' : ''})`)
      );
      for (const f of list) {
        const c = SEV_COLOR[f.severity] || chalk.white;
        console.log('  ' + c(` ${f.severity} `) + ' ' + chalk.cyan(f.file));
        console.log('    ' + f.message);
        if (f.evidence) console.log('    ' + chalk.gray('› ' + truncate(f.evidence, 160)));
      }
      console.log();
    }
  }

  const color =
    v.label === 'TOXIC' ? chalk.bgRed.white.bold :
    v.label === 'WARN' ? chalk.bgYellow.black.bold :
    chalk.bgGreen.black.bold;
  console.log(color(` ${v.label} `) + chalk.gray(`  score=${v.score}  (threshold: WARN≥5  TOXIC≥10)`));
  console.log();

  if (v.label === 'TOXIC') {
    console.log(chalk.red('✗ Do NOT install this skill without human review.'));
  } else if (v.label === 'WARN') {
    console.log(chalk.yellow('⚠ Review findings before installing.'));
  } else {
    console.log(chalk.green('✓ No high-severity signals detected. Still do a brief manual review.'));
  }
}

export function asJson(origin, result) {
  return JSON.stringify({
    tool: 'skill-lint',
    schemaVersion: 1,
    origin,
    skill: {
      name: result.frontmatter?.name || null,
      description: result.frontmatter?.description || null,
      files: result.files,
    },
    findings: result.findings,
    verdict: result.verdict,
    scoring: { CRITICAL: SCORE.CRITICAL, HIGH: SCORE.HIGH, MEDIUM: SCORE.MEDIUM, LOW: SCORE.LOW },
  }, null, 2);
}

function truncate(s, n) {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '…';
}
