export const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

export const SCORE = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 1,
};

export const TOXIC_THRESHOLD = 10;
export const WARN_THRESHOLD = 5;

export function verdict(findings) {
  const total = findings.reduce((s, f) => s + (SCORE[f.severity] || 0), 0);
  if (total >= TOXIC_THRESHOLD) return { label: 'TOXIC', score: total, exitCode: 2 };
  if (total >= WARN_THRESHOLD) return { label: 'WARN', score: total, exitCode: 1 };
  return { label: 'SAFE', score: total, exitCode: 0 };
}
