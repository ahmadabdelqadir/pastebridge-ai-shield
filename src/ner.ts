/**
 * AI Shield — optional on-device model for names, organisations and places.
 *
 * Patterns cannot find "Dana Levi" or "Northwind Trading". This pass runs a
 * small NER model (Xenova/bert-base-NER, quantized ONNX, ~110 MB, English)
 * through the transformers.js runtime the app already ships for semantic
 * search. It downloads only after the user opts in, then runs fully offline.
 *
 * transformers.js 2.x returns token labels without character offsets, so the
 * spans are rebuilt here: consecutive B-/I- tokens of one type are joined into
 * a phrase, which is then located in the source text from a moving cursor.
 */

import type { Entity, EntityKind } from './detect';

export const NER_MODEL_ID = 'Xenova/bert-base-NER';

/** Characters per model call. BERT reads 512 tokens; English averages ~4 chars a token. */
const CHUNK_CHARS = 1200;
/** Text beyond this is left to the patterns: keeps a pasted log from pinning a core. */
const MAX_MODEL_CHARS = 20_000;
const MIN_SCORE = 0.8;

export interface NerToken {
  entity: string;
  score: number;
  index: number;
  word: string;
}

const KIND_BY_LABEL: Record<string, EntityKind> = {
  PER: 'PERSON',
  ORG: 'ORG',
  LOC: 'LOCATION',
};

/**
 * People greet the assistant by name ("Hi Claude, ..."); masking that turns
 * the prompt into "Hi [PERSON_1]" and protects nobody.
 */
const ASSISTANT_NAMES = new Set([
  'claude', 'chatgpt', 'gpt', 'gemini', 'copilot', 'grok', 'perplexity', 'siri', 'alexa', 'cortana',
  'llama', 'mistral', 'deepseek', 'qwen', 'kimi', 'codex', 'cursor', 'bard', 'openai', 'anthropic',
]);

/**
 * Code identifiers the model reads as names: PaymentService, user_id,
 * os.path, getUser(). A developer pasting code needs them intact, and they
 * are not personal data.
 */
function looksLikeCode(value: string): boolean {
  if (/[_.()<>{}[\]=/\\]/.test(value)) return true;
  // InternalCapitals inside a single token: "PaymentService", "iPhone" too,
  // which is fine to keep.
  return !/\s/.test(value) && /[a-z][A-Z]/.test(value);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Turn the model's per-token labels for `text` into character spans.
 * Exported for tests: this is the part that can go wrong without the model.
 */
export function tokensToEntities(text: string, tokens: readonly NerToken[], offset = 0): Entity[] {
  interface Group { label: string; words: string[]; scores: number[]; lastIndex: number }
  const groups: Group[] = [];
  let current: Group | null = null;

  for (const t of [...tokens].sort((a, b) => a.index - b.index)) {
    const m = /^([BI])-(\w+)$/.exec(t.entity);
    if (!m) {
      current = null;
      continue;
    }
    const [, tag, label] = m;
    const continues = current && current.label === label && t.index === current.lastIndex + 1
      && (tag === 'I' || t.word.startsWith('##'));
    if (continues && current) {
      current.words.push(t.word);
      current.scores.push(t.score);
      current.lastIndex = t.index;
    } else {
      // A word piece cannot start an entity on its own: glue it to nothing.
      if (t.word.startsWith('##')) {
        current = null;
        continue;
      }
      current = { label, words: [t.word], scores: [t.score], lastIndex: t.index };
      groups.push(current);
    }
  }

  const out: Entity[] = [];
  let cursor = 0;
  for (const g of groups) {
    const kind = KIND_BY_LABEL[g.label];
    if (!kind) continue;
    const score = g.scores.reduce((a, b) => a + b, 0) / g.scores.length;
    if (score < MIN_SCORE) continue;

    // Rebuild the surface form: "##" pieces attach to the previous piece;
    // whole words may be separated by any whitespace or by nothing at all
    // around punctuation ("O'Brien", "AT&T", "Jean-Luc").
    let pattern = '';
    g.words.forEach((w, i) => {
      if (w.startsWith('##')) pattern += escapeRegExp(w.slice(2));
      else pattern += (i === 0 ? '' : '\\s*') + escapeRegExp(w);
    });
    const re = new RegExp(pattern, 'g');
    re.lastIndex = cursor;
    const found = re.exec(text);
    if (!found || found[0].length < 2) continue;
    // Extend to the whole word: the model sometimes labels only the head
    // piece of a name ("Lev" + unlabeled "##i").
    let end = found.index + found[0].length;
    while (end < text.length && /[\p{L}\p{M}]/u.test(text[end])) end++;
    let start = found.index;
    while (start > 0 && /[\p{L}\p{M}]/u.test(text[start - 1])) start--;
    cursor = end;
    const value = text.slice(start, end);
    if (ASSISTANT_NAMES.has(value.toLowerCase()) || looksLikeCode(value)) continue;
    out.push({ kind, start: start + offset, end: end + offset, value });
  }
  return out;
}

/** Split at line or sentence boundaries so no entity is cut in half. */
export function chunkText(text: string, size = CHUNK_CHARS): Array<{ start: number; text: string }> {
  const chunks: Array<{ start: number; text: string }> = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(text.length, start + size);
    if (end < text.length) {
      const window = text.slice(start, end);
      const cut = Math.max(window.lastIndexOf('\n'), window.lastIndexOf('. '), window.lastIndexOf(' '));
      if (cut > size / 2) end = start + cut + 1;
    }
    chunks.push({ start, text: text.slice(start, end) });
    start = end;
  }
  return chunks;
}

type Classifier = (text: string, opts: { ignore_labels: string[] }) => Promise<NerToken[]>;

let classifier: Classifier | null = null;
let loading: Promise<boolean> | null = null;

/** Download (first time) and load the model. Resolves false on failure. */
export function loadNerModel(cacheDir: string): Promise<boolean> {
  if (classifier) return Promise.resolve(true);
  if (loading) return loading;
  loading = (async () => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { pipeline, env } = require('@xenova/transformers');
      env.cacheDir = cacheDir;
      env.localModelPath = cacheDir;
      env.allowRemoteModels = true;
      classifier = await pipeline('token-classification', NER_MODEL_ID, { quantized: true });
      console.log('[ai-shield] Name model loaded');
      return true;
    } catch (err: any) {
      console.error('[ai-shield] Name model failed to load:', err?.message || err);
      loading = null; // allow a retry
      return false;
    }
  })();
  return loading;
}

export function isNerModelReady(): boolean {
  return classifier !== null;
}

export function unloadNerModel(): void {
  classifier = null;
  loading = null;
}

/** The `detectModel` hook for AiShield. Returns [] until the model is loaded. */
export async function detectWithModel(text: string): Promise<Entity[]> {
  const run = classifier;
  if (!run || !text) return [];
  const out: Entity[] = [];
  for (const chunk of chunkText(text.slice(0, MAX_MODEL_CHARS))) {
    if (!chunk.text.trim()) continue;
    const tokens = await run(chunk.text, { ignore_labels: ['O'] });
    out.push(...tokensToEntities(chunk.text, tokens, chunk.start));
    // Yield between chunks so a long paste never stalls the main process.
    await new Promise((r) => setImmediate(r));
  }
  return out;
}
