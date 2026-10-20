/**
 * AI Shield — placeholder vault.
 *
 * Swaps detected values for stable placeholders ("[EMAIL_1]") on the way into
 * an AI app and swaps them back when the user copies the answer out. The same
 * value always gets the same placeholder within a vault's lifetime, so a
 * conversation that spans several pastes stays coherent for the model, and an
 * answer copied out an hour later still restores.
 *
 * The vault lives in memory only. Originals never touch disk.
 */

import type { Entity, EntityKind } from './detect';

/** Placeholder label shown to the model for each kind. */
const LABEL: Record<EntityKind, string> = {
  PRIVATE_KEY: 'PRIVATE_KEY',
  SECRET: 'SECRET',
  CARD: 'CARD',
  IBAN: 'IBAN',
  SSN: 'SSN',
  EMAIL: 'EMAIL',
  PHONE: 'PHONE',
  IP: 'IP',
  PERSON: 'PERSON',
  ORG: 'ORG',
  LOCATION: 'LOCATION',
  CUSTOM: 'REDACTED',
};

const LABELS = Array.from(new Set(Object.values(LABEL)));

/**
 * Models echo placeholders back in slightly different shapes: brackets
 * dropped, swapped for <> or {}, underscore turned into a space, or with
 * markdown escaping (`\[EMAIL_1\]`). Accept all of them on the way back, but
 * only for labels we issue and only as whole tokens, so "EMAIL_10" is never
 * read as "EMAIL_1" followed by "0".
 */
const PLACEHOLDER_PATTERN = new RegExp(
  `\\\\?[\\[<{]?\\b(${LABELS.join('|')})[_ ](\\d{1,5})\\b\\\\?[\\]>}]?`,
  'g',
);

export interface MaskResult {
  text: string;
  /** One entry per replaced span, in text order. */
  replaced: Array<{ kind: EntityKind; placeholder: string }>;
}

export interface UnmaskResult {
  text: string;
  restored: number;
}

export interface VaultOptions {
  /** Forget mappings older than this (ms). Default 12 hours. */
  ttlMs?: number;
  /** Hard cap on remembered values. Oldest are dropped first. Default 5000. */
  maxEntries?: number;
  now?: () => number;
  /**
   * Placeholder counters from a previous run (see `counterSnapshot`). Without
   * them a restart would reissue "[EMAIL_1]" for a new value, and copying an
   * answer from an older conversation would restore the wrong value.
   */
  counters?: Record<string, number>;
}

interface Slot {
  placeholder: string;
  original: string;
  touchedAt: number;
}

function normalize(kind: EntityKind, value: string): string {
  if (kind === 'EMAIL' || kind === 'CUSTOM' || kind === 'PERSON' || kind === 'ORG' || kind === 'LOCATION') {
    return `${kind}:${value.trim().toLowerCase()}`;
  }
  if (kind === 'CARD' || kind === 'PHONE' || kind === 'SSN') {
    return `${kind}:${value.replace(/\D/g, '')}`;
  }
  if (kind === 'IBAN') return `${kind}:${value.replace(/\s+/g, '').toUpperCase()}`;
  return `${kind}:${value}`;
}

export class Vault {
  private readonly byKey = new Map<string, Slot>();
  private readonly byPlaceholder = new Map<string, Slot>();
  private readonly counters = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(opts: VaultOptions = {}) {
    this.ttlMs = opts.ttlMs ?? 12 * 60 * 60 * 1000;
    this.maxEntries = opts.maxEntries ?? 5000;
    this.now = opts.now ?? Date.now;
    for (const [label, n] of Object.entries(opts.counters ?? {})) {
      if (LABELS.includes(label) && Number.isSafeInteger(n) && n > 0) this.counters.set(label, n);
    }
  }

  /** Counters only — never originals — safe to persist. */
  counterSnapshot(): Record<string, number> {
    return Object.fromEntries(this.counters);
  }

  get size(): number {
    return this.byKey.size;
  }

  /**
   * Forget every original. Counters are deliberately kept: an old
   * conversation may still hold "[EMAIL_1]", and reissuing that placeholder
   * for a different value would make copying that old answer restore the
   * wrong person's email.
   */
  clear(): void {
    this.byKey.clear();
    this.byPlaceholder.clear();
  }

  mask(text: string, entities: readonly Entity[]): MaskResult {
    this.expire();
    const replaced: MaskResult['replaced'] = [];
    let out = '';
    let cursor = 0;
    for (const e of [...entities].sort((a, b) => a.start - b.start)) {
      if (e.start < cursor) continue; // caller should pass non-overlapping spans
      const slot = this.slotFor(e.kind, e.value);
      out += text.slice(cursor, e.start) + slot.placeholder;
      cursor = e.end;
      replaced.push({ kind: e.kind, placeholder: slot.placeholder });
    }
    out += text.slice(cursor);
    return { text: out, replaced };
  }

  unmask(text: string): UnmaskResult {
    if (this.byPlaceholder.size === 0 || !text) return { text, restored: 0 };
    this.expire();
    let restored = 0;
    PLACEHOLDER_PATTERN.lastIndex = 0;
    const out = text.replace(PLACEHOLDER_PATTERN, (match, label: string, num: string) => {
      const slot = this.byPlaceholder.get(`[${label}_${Number(num)}]`);
      if (!slot) return match;
      slot.touchedAt = this.now();
      restored++;
      return slot.original;
    });
    return { text: out, restored };
  }

  /** True if the text carries at least one placeholder this vault can restore. */
  hasPlaceholders(text: string): boolean {
    if (this.byPlaceholder.size === 0 || !text) return false;
    PLACEHOLDER_PATTERN.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PLACEHOLDER_PATTERN.exec(text)) !== null) {
      if (this.byPlaceholder.has(`[${m[1]}_${Number(m[2])}]`)) return true;
    }
    return false;
  }

  private slotFor(kind: EntityKind, value: string): Slot {
    const key = normalize(kind, value);
    const existing = this.byKey.get(key);
    if (existing) {
      existing.touchedAt = this.now();
      return existing;
    }
    const label = LABEL[kind];
    const n = (this.counters.get(label) ?? 0) + 1;
    this.counters.set(label, n);
    const slot: Slot = { placeholder: `[${label}_${n}]`, original: value, touchedAt: this.now() };
    this.byKey.set(key, slot);
    this.byPlaceholder.set(slot.placeholder, slot);
    this.evictOverflow();
    return slot;
  }

  private expire(): void {
    const cutoff = this.now() - this.ttlMs;
    for (const [key, slot] of this.byKey) {
      if (slot.touchedAt < cutoff) {
        this.byKey.delete(key);
        this.byPlaceholder.delete(slot.placeholder);
      }
    }
  }

  private evictOverflow(): void {
    if (this.byKey.size <= this.maxEntries) return;
    const oldest = [...this.byKey.entries()].sort((a, b) => a[1].touchedAt - b[1].touchedAt);
    for (const [key, slot] of oldest.slice(0, this.byKey.size - this.maxEntries)) {
      this.byKey.delete(key);
      this.byPlaceholder.delete(slot.placeholder);
    }
  }
}
