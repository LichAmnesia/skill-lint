import { SEVERITY } from '../severity.js';
import { INTERPRETER_RE } from '../classify.js';

const BASE64_LONG = /\b[A-Za-z0-9+/]{80,}={0,2}\b/;
// Short base64 (≥24 chars) is still dangerous when decoded-and-piped to a
// shell in the same file — a b64-encoded `curl url|sh` payload is ~56 chars.
const BASE64_MED = /\b[A-Za-z0-9+/]{24,}={0,2}\b/;
const BASE64_DECODE = /(?:base64\s+(?:-d|--decode|-D)|atob\s*\()/i;
// Decode piped to ANY interpreter (including xxd hex, openssl base64).
// INTERPRETER_RE tolerates /bin/bash, env bash, sudo python3, etc.
const BASE64_DECODE_PIPE_SHELL = new RegExp(
  String.raw`\b(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r\s+-p|openssl\s+(?:enc\s+)?-base64\s+-d)[^\n]*\|\s*` + INTERPRETER_RE + String.raw`\b`,
  'i'
);
const HEX_LONG = /(?:\\x[0-9a-f]{2}){10,}/i;
const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
const HOMOGLYPH_CYRILLIC = /[\u0430-\u044F]{3,}/; // Cyrillic letters inside otherwise-Latin text

export default {
  id: 'R02',
  ast: 'AST04',
  title: 'Obfuscation / hidden content',
  defaultSeverity: SEVERITY.HIGH,
  check(ctx) {
    const findings = [];
    for (const f of ctx.files) {
      if (!ctx.isText(f)) continue;
      const text = ctx.readText(f);
      if (!text) continue;

      // Zero-width / bidi / homoglyph checks run on FULL text (steganography
      // hides inside prose). Base64 payload checks only run on scannable text
      // (fences for readme/doc) to avoid flagging legit base64 examples.
      if (ZERO_WIDTH.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Zero-width / bidi control chars present (steganography risk)'));
      }

      const scanText = ctx.scanText(f);
      if (scanText) {
        // CRITICAL reserved for decode-and-execute pipelines.
        if (BASE64_DECODE_PIPE_SHELL.test(scanText)) {
          findings.push(mk(f, SEVERITY.CRITICAL, 'base64 -d | sh — RCE via decoded payload'));
        }
        // Command-substitution variant: X=$(... | base64 -d); eval "$X"
        // Detect: any `base64 -d` (or xxd -r -p) inside $(...) OR backticks,
        // co-occurring with `eval $VAR` / `bash $VAR` / `sh $VAR` / `eval "$(...)"`.
        const decodeInCmdSub = /\$\([^)]*\bbase64\s+(?:-d|--decode|-D)[^)]*\)|`[^`]*\bbase64\s+(?:-d|--decode|-D)[^`]*`|\$\([^)]*\bxxd\s+-r\s+-p[^)]*\)/i;
        const evalVar = /\b(?:eval|bash|sh|zsh|ksh|python3?|node|perl|ruby)\s+["']?\$\{?\w+\}?/i;
        const evalCmdSub = /\beval\s+["']?\$\([^)]*\bbase64\s+(?:-d|--decode|-D)[^)]*\)/i;
        if (evalCmdSub.test(scanText) || (decodeInCmdSub.test(scanText) && evalVar.test(scanText))) {
          findings.push(mk(f, SEVERITY.CRITICAL, 'base64-decoded command substitution executed via eval/var — obfuscated RCE'));
        } else if (BASE64_DECODE.test(scanText) && BASE64_LONG.test(scanText)) {
          // Long blob + decode somewhere: still noteworthy but not neccessarily RCE.
          findings.push(mk(f, SEVERITY.HIGH, 'Long base64 blob with base64-decode in same file — review for hidden payload'));
        } else if (BASE64_DECODE.test(scanText) && BASE64_MED.test(scanText)) {
          findings.push(mk(f, SEVERITY.MEDIUM, 'Short base64 blob with base64-decode — review'));
        } else if (BASE64_LONG.test(scanText) && /\.(sh|md|py|js|ts)$/.test(f.relPath)) {
          findings.push(mk(f, SEVERITY.MEDIUM, 'Long base64-looking blob in script/doc'));
        }
        if (HEX_LONG.test(scanText)) {
          findings.push(mk(f, SEVERITY.HIGH, 'Long \\x hex escape sequence (possible hidden command)'));
        }
      }

      // Cyrillic letters mixed into ASCII-dominant file: crude homoglyph flag
      const asciiRatio = asciiLetterRatio(text);
      if (asciiRatio > 0.5 && HOMOGLYPH_CYRILLIC.test(text) && !/\.(zh|ru|uk)\./.test(f.relPath)) {
        findings.push(mk(f, SEVERITY.MEDIUM, 'Cyrillic chars in ASCII-dominant file (homoglyph risk)'));
      }
    }
    return findings;
  },
};

function asciiLetterRatio(s) {
  let a = 0, t = 0;
  for (const c of s) {
    if (/\S/.test(c)) t++;
    if (/[a-zA-Z]/.test(c)) a++;
  }
  return t ? a / t : 0;
}

function mk(f, severity, message) {
  return {
    ruleId: 'R02',
    ast: 'AST04',
    severity,
    title: 'Obfuscation / hidden content',
    file: f.relPath,
    evidence: '',
    message,
  };
}

function severityOverride(s) { return s; }
