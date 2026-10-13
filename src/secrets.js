export const SECRET_PATTERNS = [
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20}\b/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/],
  ['Stripe key', /\b[sr]k_live_[A-Za-z0-9]{20,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['private key', /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/],
  ['OpenAI key', /\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b/],
  ['password in URL', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s/@$]{3,}@[^\s]+/i],
];
export const SECRET_NAME = /(^|_)(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH|CLIENT_SECRET|DB_PASS|SIGNING_KEY|ENCRYPTION_KEY|SAS)($|_)/i;
const PLACEHOLDER = /^(|changeme|change_me|example|dummy|test|placeholder|xxx+|<.*>|\$\{?[A-Za-z_][\w]*\}?.*|\*+|none|null|false|true|0|1|yes|no|\/run\/secrets\/.*|\/.*_file|.*_FILE)$/i;
export function findSecret(text) { for (const [name, re] of SECRET_PATTERNS) { const m = String(text).match(re); if (m) return { name, value: m[0] }; } return null; }
export function isSecretAssignment(key, value) { return SECRET_NAME.test(key) && !/_FILE$|_PATH$|_URL$|_HOST$|_USER(NAME)?$|_NAME$|_ID$|_ENABLED$|_LENGTH$/i.test(key) && !PLACEHOLDER.test(String(value ?? '').trim().replace(/^["']|["']$/g, '')); }
export const mask = (v) => { const s = String(v); return s.length <= 6 ? '***' : `${s.slice(0, 3)}…${s.slice(-2)} (${s.length} chars)`; };
