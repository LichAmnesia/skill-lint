import { SEVERITY } from '../severity.js';

const BASE64_LONG = /\b[A-Za-z0-9+/]{80,}={0,2}\b/;
const BASE64_DECODE = /(?:base64\s+(?:-d|--decode|-D)|atob\s*\()/i;
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

      if (ZERO_WIDTH.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Zero-width / bidi control chars present (steganography risk)'));
      }
      if (BASE64_DECODE.test(text) && BASE64_LONG.test(text)) {
        findings.push(mk(f, SEVERITY.CRITICAL, 'Base64 blob decoded inline — possible hidden payload', severityOverride(SEVERITY.CRITICAL)));
      } else if (BASE64_LONG.test(text) && /\.(sh|md|py|js|ts)$/.test(f.relPath)) {
        findings.push(mk(f, SEVERITY.MEDIUM, 'Long base64-looking blob in script/doc'));
      }
      if (HEX_LONG.test(text)) {
        findings.push(mk(f, SEVERITY.HIGH, 'Long \\x hex escape sequence (possible hidden command)'));
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
