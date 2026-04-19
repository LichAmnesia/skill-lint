import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, stat, readdir } from 'node:fs/promises';
import { join, resolve, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);

/**
 * Parse a GitHub URL that may include /tree/<ref>/<subdir>.
 * Returns { cloneUrl, ref, subdir } or null if not a parseable GitHub URL.
 */
export function parseGithubUrl(input) {
  try {
    const u = new URL(input);
    if (u.hostname !== 'github.com') return null;
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length < 2) return null;
    const [owner, repoRaw, kind, ref, ...subParts] = parts;
    const repo = repoRaw.replace(/\.git$/, '');
    const cloneUrl = `https://github.com/${owner}/${repo}.git`;
    if (kind === 'tree' || kind === 'blob') {
      return { cloneUrl, ref: ref || 'HEAD', subdir: subParts.join('/') || '' };
    }
    return { cloneUrl, ref: 'HEAD', subdir: '' };
  } catch {
    return null;
  }
}

/**
 * Resolve the input target into a local directory that contains the skill.
 * Returns { dir, cleanup, origin }. Caller MUST invoke cleanup().
 */
export async function fetchTarget(input) {
  // Local path case
  if (!/^https?:\/\//i.test(input)) {
    const abs = isAbsolute(input) ? input : resolve(process.cwd(), input);
    const s = await stat(abs).catch(() => null);
    if (!s || !s.isDirectory()) {
      throw new Error(`Local path not found or not a directory: ${abs}`);
    }
    return { dir: abs, cleanup: async () => {}, origin: `local:${abs}` };
  }

  // GitHub URL case
  const parsed = parseGithubUrl(input);
  if (!parsed) {
    throw new Error(`Only GitHub URLs are supported. Got: ${input}`);
  }

  const tmpRoot = await mkdtemp(join(tmpdir(), 'skill-lint-'));
  const cloneArgs = ['clone', '--depth', '1', '--single-branch'];
  if (parsed.ref && parsed.ref !== 'HEAD') {
    cloneArgs.push('--branch', parsed.ref);
  }
  cloneArgs.push(parsed.cloneUrl, tmpRoot);

  try {
    await exec('git', cloneArgs, { timeout: 60_000 });
  } catch (err) {
    // Fallback: try without --branch (ref might be a commit or default)
    if (parsed.ref && parsed.ref !== 'HEAD') {
      const fallback = ['clone', '--depth', '1', parsed.cloneUrl, tmpRoot + '-fb'];
      await exec('git', fallback, { timeout: 60_000 });
      await rm(tmpRoot, { recursive: true, force: true });
      const dir = parsed.subdir ? join(tmpRoot + '-fb', parsed.subdir) : tmpRoot + '-fb';
      return {
        dir,
        cleanup: () => rm(tmpRoot + '-fb', { recursive: true, force: true }),
        origin: input,
      };
    }
    await rm(tmpRoot, { recursive: true, force: true });
    throw err;
  }

  const dir = parsed.subdir ? join(tmpRoot, parsed.subdir) : tmpRoot;
  const s = await stat(dir).catch(() => null);
  if (!s) {
    await rm(tmpRoot, { recursive: true, force: true });
    throw new Error(`Subdir not found in repo: ${parsed.subdir}`);
  }

  return {
    dir,
    cleanup: () => rm(tmpRoot, { recursive: true, force: true }),
    origin: input,
  };
}

/**
 * Walk a directory and return file entries with { absPath, relPath, size, ext }.
 * Skips .git, node_modules, and files larger than 2 MiB.
 */
export async function walkFiles(root, maxBytes = 2 * 1024 * 1024) {
  const out = [];
  async function rec(dir, rel) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const abs = join(dir, e.name);
      const nextRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        await rec(abs, nextRel);
      } else if (e.isFile()) {
        const st = await stat(abs).catch(() => null);
        if (!st) continue;
        const ext = (e.name.match(/\.[^.]+$/)?.[0] || '').toLowerCase();
        out.push({
          absPath: abs,
          relPath: nextRel,
          size: st.size,
          ext,
          tooLarge: st.size > maxBytes,
        });
      }
    }
  }
  await rec(root, '');
  return out;
}
