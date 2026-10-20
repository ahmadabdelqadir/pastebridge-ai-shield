/**
 * AI Shield — entity detection.
 *
 * Finds the spans of text that must not reach an AI model verbatim: secrets
 * (API keys, tokens, private keys, passwords in config) and personal data
 * (emails, phone numbers, cards, IBANs, SSNs, public IPs), plus any terms the
 * user listed themselves (client names, project code names).
 *
 * Unlike the sync privacy filter, which only needs a yes/no answer, masking
 * needs exact spans, and it needs to mask only the secret part of a match
 * (the value of `API_KEY=...`, not the variable name the model needs to see).
 *
 * Pure module: no Electron, no I/O. Names and other free-text entities come
 * from an optional model pass layered on top (see ner.ts); this file is the
 * deterministic floor that always runs.
 */

export type EntityKind =
  | 'PRIVATE_KEY'
  | 'SECRET'
  | 'CARD'
  | 'IBAN'
  | 'SSN'
  | 'EMAIL'
  | 'PHONE'
  | 'IP'
  | 'PERSON'
  | 'ORG'
  | 'LOCATION'
  | 'CUSTOM';

export interface Entity {
  kind: EntityKind;
  start: number;
  /** Exclusive end offset. */
  end: number;
  value: string;
}

export interface DetectOptions {
  /** Kinds to report. Defaults to every kind. */
  kinds?: ReadonlySet<EntityKind>;
  /** User-supplied terms, matched case-insensitively on word boundaries. */
  customTerms?: readonly string[];
}

/** Higher wins when two spans overlap. */
const PRIORITY: Record<EntityKind, number> = {
  PRIVATE_KEY: 100,
  SECRET: 90,
  CUSTOM: 85,
  CARD: 80,
  IBAN: 75,
  SSN: 70,
  EMAIL: 60,
  PHONE: 50,
  IP: 40,
  PERSON: 30,
  ORG: 20,
  LOCATION: 10,
};

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s+/g, '').toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const chunk = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of chunk) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

function isPublicIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 0 || a === 127 || a === 10 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  return true;
}

// ---------------------------------------------------------------------------
// Patterns
//
// Each rule yields the span to mask. `group` selects a capture group when only
// part of the match is secret; the group must be the LAST thing in the match
// or followed only by a delimiter we do not mask.
// ---------------------------------------------------------------------------

interface Rule {
  kind: EntityKind;
  pattern: RegExp;
  group?: number;
  validate?: (value: string) => boolean;
}

const RULES: Rule[] = [
  {
    kind: 'PRIVATE_KEY',
    pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  // Provider-shaped credentials. Prefixes come from the providers' own docs
  // and the gitleaks rule set; each is distinctive enough to need no context.
  {
    kind: 'SECRET',
    pattern: new RegExp(
      '\\b(?:'
        + 'sk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}'     // OpenAI, Anthropic
        + '|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}'                // Stripe
        + '|(?:AKIA|ASIA)[0-9A-Z]{16}'                               // AWS access key id
        + '|gh[pousr]_[A-Za-z0-9]{36,}'                              // GitHub
        + '|github_pat_[A-Za-z0-9_]{22,}'
        + '|glpat-[A-Za-z0-9_-]{20,}'                                // GitLab
        + '|xox[abposr]-[A-Za-z0-9-]{10,}'                           // Slack
        + '|AIza[0-9A-Za-z_-]{35}'                                   // Google
        + '|SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}'            // SendGrid
        + '|npm_[A-Za-z0-9]{36}'                                     // npm
        + '|hf_[A-Za-z0-9]{30,}'                                     // Hugging Face
        + '|eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' // JWT
        + ')',
      'g',
    ),
  },
  { kind: 'SECRET', pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  // Bearer / Basic credentials: mask the credential, keep the scheme.
  { kind: 'SECRET', pattern: /\b(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})/g, group: 1 },
  // user:password@host in connection strings: mask the password only.
  { kind: 'SECRET', pattern: /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/gi, group: 1 },
  // Secret-looking query parameters.
  {
    kind: 'SECRET',
    pattern: /[?&](?:[A-Za-z0-9.-]*_)?(?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|key|secret|client_secret|password|sig|signature)=([^&\s#"']{8,})/gi,
    group: 1,
  },
  // Assignments in code, config and .env files: `password: hunter2`,
  // `DB_PASSWORD="..."`, `"apiKey": "..."`. Mask the value, keep the name.
  {
    kind: 'SECRET',
    // Anchored on the keyword, not on a greedy name prefix: `\b[\w.-]*keyword`
    // backtracks quadratically over long dotted runs (minified code). The
    // variable-length lookbehind leaves URL parameters (`?db_password=`) to
    // the rule above, which stops at &.
    pattern: /(?<![?&][A-Za-z0-9_.-]*)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|AccountKey|SharedAccessKey)["']?\s*[:=]\s*["']?([^\s"',;]{6,})/gi,
    group: 1,
    // `password: ********` and `token = null` are not secrets.
    validate: (v) => !/^(?:\*+|x+|null|none|undefined|true|false|changeme|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\})$/i.test(v),
  },
  {
    kind: 'EMAIL',
    // Starts only where a local part can start (lookbehind), never inside
    // one: `\b` restarts at every dot of a long dotted run and makes the scan
    // quadratic on minified code.
    pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b/g,
  },
  {
    kind: 'CARD',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (v) => {
      const digits = v.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19 && /^[2-6]/.test(digits) && luhnValid(digits);
    },
  },
  {
    kind: 'IBAN',
    pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g,
    validate: ibanValid,
  },
  // US SSN. Separators required: nine bare digits are far more often an
  // order number than an SSN, and a false mask is not free here.
  { kind: 'SSN', pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  // Phone numbers: an explicit international prefix, or a common grouped
  // national format. Bare digit runs are left alone (ids, amounts, dates).
  {
    kind: 'PHONE',
    pattern: /(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){2,4}|\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\b\d{3}[.-]\d{3}[.-]\d{4}|\b0\d{1,2}[ -]\d{3}[ -]?\d{4})\b/g,
    validate: (v) => {
      const digits = v.replace(/\D/g, '').length;
      return digits >= 9 && digits <= 15;
    },
  },
  { kind: 'IP', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, validate: isPublicIpv4 },
];

/**
 * Characters that render as nothing but that models read: Unicode tag
 * characters (U+E0000–E007F, the "ASCII smuggling" channel), bidi embeddings,
 * overrides and isolates, zero-width space, word joiner and invisible
 * operators, a BOM inside text, and the Mongolian vowel separator. ZWJ and
 * ZWNJ are kept: emoji sequences and several scripts need them.
 */
const INVISIBLE_PATTERN = /[\u{E0000}-\u{E007F}‪-‮⁦-⁩​⁠-⁤﻿᠎]/gu;

export function stripInvisible(text: string): { text: string; removed: number } {
  let removed = 0;
  const out = text.replace(INVISIBLE_PATTERN, () => {
    removed++;
    return '';
  });
  return { text: out, removed };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

export function detectEntities(text: string, opts: DetectOptions = {}): Entity[] {
  if (!text) return [];
  const wanted = opts.kinds;
  const found: Entity[] = [];

  for (const rule of RULES) {
    if (wanted && !wanted.has(rule.kind)) continue;
    rule.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.pattern.exec(text)) !== null) {
      if (m[0].length === 0) {
        rule.pattern.lastIndex++;
        continue;
      }
      const value = rule.group ? m[rule.group] : m[0];
      if (!value) continue;
      if (rule.validate && !rule.validate(value)) continue;
      const start = rule.group ? m.index + m[0].lastIndexOf(value) : m.index;
      found.push({ kind: rule.kind, start, end: start + value.length, value });
    }
  }

  if (opts.customTerms && (!wanted || wanted.has('CUSTOM'))) {
    for (const term of opts.customTerms) {
      const trimmed = term.trim();
      if (trimmed.length < 2) continue;
      // Word boundaries only where the term itself starts/ends with a word
      // character, so terms like "C++ team" or "@acme" still match.
      const left = /^\w/.test(trimmed) ? '\\b' : '';
      const right = /\w$/.test(trimmed) ? '\\b' : '';
      const re = new RegExp(`${left}${escapeRegExp(trimmed)}${right}`, 'gi');
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        found.push({ kind: 'CUSTOM', start: m.index, end: m.index + m[0].length, value: m[0] });
      }
    }
  }

  return resolveOverlaps(found);
}

/**
 * Keep a non-overlapping set: higher priority first, then the longer span.
 * Exported because the model pass merges its own spans through it.
 */
export function resolveOverlaps(entities: Entity[]): Entity[] {
  const ranked = [...entities].sort(
    (a, b) => PRIORITY[b.kind] - PRIORITY[a.kind] || (b.end - b.start) - (a.end - a.start) || a.start - b.start,
  );
  const kept: Entity[] = [];
  for (const e of ranked) {
    if (!kept.some((k) => e.start < k.end && k.start < e.end)) kept.push(e);
  }
  return kept.sort((a, b) => a.start - b.start);
}
