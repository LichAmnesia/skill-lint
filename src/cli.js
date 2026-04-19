import { fetchTarget } from './fetcher.js';
import { scanDir } from './scanner.js';
import { printHumanReport, asJson } from './report.js';
import { cp, mkdir, stat } from 'node:fs/promises';
import { join, basename, resolve } from 'node:path';
import { homedir } from 'node:os';

const USAGE = `
skill-lint — Claude Code / agent skill security scanner

Usage:
  npx skill-lint <github-url-or-local-path> [options]

Examples:
  npx skill-lint https://github.com/user/my-skill
  npx skill-lint https://github.com/user/repo/tree/main/skills/my-skill
  npx skill-lint ./local-skill
  npx skill-lint <url> --json
  npx skill-lint <url> --install ~/.claude/skills/

Options:
  --json                  Output JSON (machine-readable)
  --install <dir>         If verdict is SAFE, copy skill into <dir>
  --force-install         Install even if verdict is WARN (never TOXIC)
  --help, -h              Show this help
  --version, -v           Show version

Exit codes:
  0 = SAFE · 1 = WARN · 2 = TOXIC · 3 = scanner error
`;

export async function runCli(argv) {
  const args = parseArgs(argv);

  if (args.help) { console.log(USAGE); return; }
  if (args.version) {
    const pkg = await loadPkg();
    console.log(pkg.version);
    return;
  }
  if (!args.target) {
    console.error(USAGE);
    process.exit(3);
  }

  const fetched = await fetchTarget(args.target);
  let result;
  try {
    result = await scanDir(fetched.dir);
  } finally {
    // Do not delete yet if we may need to copy on install
  }

  if (args.json) {
    console.log(asJson(fetched.origin, result));
  } else {
    printHumanReport(fetched.origin, result);
  }

  // Install path
  if (args.install) {
    const installDir = expandTilde(args.install);
    const canInstall =
      result.verdict.label === 'SAFE' ||
      (result.verdict.label === 'WARN' && args.forceInstall);
    if (canInstall) {
      await mkdir(installDir, { recursive: true });
      const name = result.frontmatter?.name || basename(fetched.dir);
      const dest = join(installDir, sanitizeName(name));
      await cp(fetched.dir, dest, {
        recursive: true,
        filter: (src) => !/\/\.git(\/|$)/.test(src),
      });
      if (!args.json) {
        console.log(`\n✓ Installed to: ${dest}`);
      }
    } else if (result.verdict.label === 'TOXIC') {
      if (!args.json) console.error('\n✗ Install blocked: verdict is TOXIC.');
    } else if (result.verdict.label === 'WARN') {
      if (!args.json) console.error('\n✗ Install blocked: verdict is WARN. Use --force-install to override.');
    }
  }

  await fetched.cleanup();
  process.exit(result.verdict.exitCode);
}

function parseArgs(argv) {
  const out = { target: null, json: false, install: null, forceInstall: false, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--version' || a === '-v') out.version = true;
    else if (a === '--json') out.json = true;
    else if (a === '--install') out.install = argv[++i];
    else if (a === '--force-install') out.forceInstall = true;
    else if (!out.target && !a.startsWith('-')) out.target = a;
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(3);
    }
  }
  return out;
}

function expandTilde(p) {
  if (p.startsWith('~/') || p === '~') return p.replace('~', homedir());
  return resolve(p);
}

function sanitizeName(n) {
  return String(n).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'skill';
}

async function loadPkg() {
  const { readFile } = await import('node:fs/promises');
  const url = new URL('../package.json', import.meta.url);
  return JSON.parse(await readFile(url, 'utf8'));
}
