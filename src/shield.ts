/**
 * AI Shield — the controller.
 *
 * One invariant, enforced on every foreground change and every copy:
 *
 *   - While an AI app is in front, the clipboard holds the MASKED form:
 *     sensitive values replaced by placeholders.
 *   - While anything else is in front, the clipboard holds the REAL form:
 *     placeholders from this vault replaced by the values they stand for.
 *
 * So the user copies and pastes exactly as before. Pasting into ChatGPT pastes
 * "[EMAIL_1]"; copying ChatGPT's answer and pasting it into Outlook pastes the
 * real address. Nothing is intercepted, no keystroke is synthesized.
 *
 * Two rules keep it safe:
 *   - In an AI app we only ever mask. We never restore there, even if a value
 *     the vault knows would no longer be detected (a custom term the user just
 *     removed, a name the optional model found): restoring inside the AI app
 *     is exactly the leak this exists to prevent.
 *   - Outside, we only touch the clipboard when it holds our placeholders or
 *     our own masked text. Ordinary clipboards are never rewritten.
 *
 * Pictures follow the same invariant. A screenshot's text is read on this PC
 * (off the main thread, as soon as it is copied, so the result is usually
 * ready before the user reaches the AI app) and the sensitive spans are
 * painted out of a copy. The clipboard is touched only when something was
 * found, and the exact original picture comes back on leaving the AI app.
 */

import { EventEmitter } from 'events';
import { detectEntities, resolveOverlaps, stripInvisible, type Entity, type EntityKind } from './detect';
import { entityBoxes, layoutText, type OcrBox, type OcrLine } from './image';
import { matchAiTarget, type AiTarget, type ForegroundWindow } from './targets';
import type { Vault } from './vault';

export interface ClipboardSnapshot {
  text: string;
  html?: string;
  rtf?: string;
}

export interface ClipboardImage {
  /** Identity of the pixels: reading the same picture twice gives the same key. */
  key: string;
  width: number;
  height: number;
  /** The picture as PNG, the clipboard's own bytes where it had them. Held to put back. */
  png: Buffer;
}

export interface ShieldClipboard {
  readText(): string;
  /** Every format we can restore later. */
  readSnapshot(): ClipboardSnapshot;
  /** Plain text only. The owner must not treat this write as a user copy. */
  writeText(text: string): void;
  writeSnapshot(snapshot: ClipboardSnapshot): void;
  /**
   * The picture on the clipboard, or null when it holds none. A port without
   * the three picture methods never has its pictures touched.
   */
  readImage?(): ClipboardImage | null;
  /** Put a held original back, byte for byte. */
  writeImage?(image: ClipboardImage): void;
  /**
   * Write `image` with `boxes` painted out. Returns the key of the picture now
   * on the clipboard, or null when the write failed.
   */
  writeMaskedImage?(image: ClipboardImage, boxes: readonly OcrBox[]): string | null;
}

export interface ShieldSettings {
  enabled: boolean;
  kinds: ReadonlySet<EntityKind>;
  customTerms: readonly string[];
  disabledTargets: ReadonlySet<string>;
  extraProcesses: readonly string[];
  /** Paint sensitive text out of pictures too. */
  images: boolean;
}

export interface MaskedEvent {
  target: AiTarget;
  count: number;
  kinds: EntityKind[];
  /** Invisible characters stripped (possible prompt injection). */
  invisibleRemoved: number;
  /** Set when the items were painted out of a picture: the masked picture's key. */
  imageKey?: string;
}

export interface RestoredEvent {
  count: number;
  /** 'snapshot' = left the AI app without pasting; the original came back whole. */
  via: 'snapshot' | 'placeholders';
  /** The original that came back is a picture. */
  image?: boolean;
}

export interface AiShieldDeps {
  clipboard: ShieldClipboard;
  vault: Vault;
  settings: () => ShieldSettings;
  /**
   * Optional slower detector (a local model for names, organisations,
   * places). Its spans are merged over the pattern detector's. When it is not
   * ready by the time the user reaches an AI app, the pattern mask goes in at
   * once and is upgraded when the model answers, if the clipboard is still
   * ours.
   */
  detectModel?: (text: string) => Promise<Entity[]>;
  /**
   * Reads the text in a picture, with positions. Must not block the caller
   * (the runtime runs Tesseract in a worker thread).
   */
  recognizeImage?: (image: ClipboardImage) => Promise<OcrLine[]>;
  now?: () => number;
}

const MODEL_CACHE_SIZE = 20;
const OCR_CACHE_SIZE = 8;

type Settled<T> = Promise<T> & { settled?: T };

export class AiShield extends EventEmitter {
  private target: AiTarget | null = null;
  private pausedUntil = 0;
  /** The masked text we wrote, and what it replaced. */
  private swap: { masked: string; original: ClipboardSnapshot } | null = null;
  /** The masked picture we wrote (by key), and the picture it replaced. */
  private imageSwap: { maskedKey: string; original: ClipboardImage } | null = null;
  private readonly modelCache = new Map<string, Promise<Entity[]>>();
  private readonly ocrCache = new Map<string, Settled<OcrLine[]>>();
  private readonly now: () => number;

  constructor(private readonly deps: AiShieldDeps) {
    super();
    this.now = deps.now ?? Date.now;
  }

  get activeTarget(): AiTarget | null {
    return this.target;
  }

  get paused(): boolean {
    return this.now() < this.pausedUntil;
  }

  /** The user wants the real value through, so the original goes back first. */
  pause(ms: number): void {
    this.restoreIfOurs();
    this.pausedUntil = this.now() + ms;
    this.emit('paused', this.pausedUntil);
  }

  /**
   * If the clipboard still holds our masked copy, put the original back.
   * Called whenever the shield stops enforcing (pause, switch-off, quit):
   * otherwise the user is left with placeholders and no way to get the
   * original, because the vault may be cleared next.
   */
  restoreIfOurs(): void {
    this.restoreImageIfOurs();
    const swap = this.swap;
    if (!swap) return;
    this.swap = null;
    if (this.safeRead() !== swap.masked) return;
    this.deps.clipboard.writeSnapshot(swap.original);
    this.emit('restored', { count: 0, via: 'snapshot' } satisfies RestoredEvent);
  }

  /** Drop the held original without restoring it ("forget everything"). */
  forget(): void {
    this.swap = null;
    this.imageSwap = null;
    this.modelCache.clear();
    this.ocrCache.clear();
  }

  resume(): void {
    this.pausedUntil = 0;
    this.emit('paused', 0);
    this.reconcile();
  }

  onForeground(win: ForegroundWindow): void {
    const s = this.deps.settings();
    const next = matchAiTarget(win, { disabled: s.disabledTargets, extraProcesses: s.extraProcesses });
    const changed = (next?.id ?? null) !== (this.target?.id ?? null);
    this.target = next;
    if (changed) this.emit('target', next);
    this.reconcile();
  }

  onClipboardChanged(): void {
    const text = this.safeRead();
    // Warm the model while the user is still elsewhere, so the full mask is
    // ready by the time they switch to the AI app.
    if (text && !this.target && this.deps.settings().enabled) void this.modelEntities(stripInvisible(text).text);
    if (text) {
      this.reconcile();
      return;
    }
    // A picture: start reading it now, wherever the user is, so the result is
    // ready by the time they reach the AI app.
    const s = this.deps.settings();
    const image = s.enabled && s.images && !this.paused ? this.safeReadImage() : null;
    if (image && image.key !== this.imageSwap?.maskedKey) void this.readImageText(image);
    this.reconcileWith(image ?? undefined);
  }

  /** Bring the clipboard in line with the invariant. Safe to call any time. */
  reconcile(): void {
    this.reconcileWith(undefined);
  }

  /** `image`: the clipboard's picture, when the caller has just read it. */
  private reconcileWith(image: ClipboardImage | undefined): void {
    const s = this.deps.settings();
    if (!s.enabled || this.paused) {
      this.restoreIfOurs();
      return;
    }
    const text = this.safeRead();
    if (!text) {
      this.reconcileImage(s, image);
      return;
    }
    // Text has replaced any picture we masked: there is nothing to put back.
    this.imageSwap = null;
    if (this.target) this.ensureMasked(text, s, this.target);
    else this.ensureReal(text);
  }

  private ensureMasked(raw: string, s: ShieldSettings, target: AiTarget): void {
    if (this.swap && raw === this.swap.masked) return; // already ours
    // Detection runs on the text the model will actually receive: invisible
    // characters out first, so a zero-width space cannot split a key in two
    // and slip past the patterns.
    const clean = stripInvisible(raw);
    const entities = this.patternEntities(clean.text, s);
    const cached = this.cachedModelEntities(clean.text);
    const merged = cached ? resolveOverlaps([...entities, ...cached.filter((e) => s.kinds.has(e.kind))]) : entities;
    if (merged.length > 0 || clean.removed > 0) {
      this.writeMasked(clean.text, clean.removed, merged, this.deps.clipboard.readSnapshot(), target);
    }
    if (!cached && this.deps.detectModel) void this.upgradeWithModel(raw, clean.text, clean.removed, target);
  }

  private writeMasked(
    cleanText: string,
    invisibleRemoved: number,
    entities: Entity[],
    original: ClipboardSnapshot,
    target: AiTarget,
  ): void {
    const masked = this.deps.vault.mask(cleanText, entities);
    this.swap = { masked: masked.text, original };
    this.deps.clipboard.writeText(masked.text);
    this.emit('masked', {
      target,
      count: masked.replaced.length,
      kinds: Array.from(new Set(masked.replaced.map((r) => r.kind))),
      invisibleRemoved,
    } satisfies MaskedEvent);
  }

  private async upgradeWithModel(raw: string, cleanText: string, invisibleRemoved: number, target: AiTarget): Promise<void> {
    const found = await this.modelEntities(cleanText);
    const s = this.deps.settings();
    if (!s.enabled || this.paused || this.target?.id !== target.id) return;
    const modelHits = found.filter((e) => s.kinds.has(e.kind));
    if (modelHits.length === 0) return;
    // Only touch the clipboard if it still holds the original text, or the
    // pattern-masked version we wrote for it. Anything else is a newer copy.
    const current = this.safeRead();
    const ours = this.swap && current === this.swap.masked && this.swap.original.text === raw;
    if (current !== raw && !ours) return;
    const original = ours ? this.swap!.original : this.deps.clipboard.readSnapshot();
    const merged = resolveOverlaps([...this.patternEntities(cleanText, s), ...modelHits]);
    this.writeMasked(cleanText, invisibleRemoved, merged, original, target);
  }

  private ensureReal(text: string): void {
    const swap = this.swap;
    if (swap && text === swap.masked) {
      // Left the AI app with our masked text still on the clipboard: put the
      // original back with every format it had.
      this.swap = null;
      this.deps.clipboard.writeSnapshot(swap.original);
      this.emit('restored', { count: 0, via: 'snapshot' } satisfies RestoredEvent);
      return;
    }
    this.swap = null;
    if (!this.deps.vault.hasPlaceholders(text)) return;
    const restored = this.deps.vault.unmask(text);
    if (restored.restored === 0) return;
    this.deps.clipboard.writeText(restored.text);
    this.emit('restored', { count: restored.restored, via: 'placeholders' } satisfies RestoredEvent);
  }

  // ---------------------------------------------------------------- pictures

  private reconcileImage(s: ShieldSettings, prefetched: ClipboardImage | undefined): void {
    if (!this.deps.clipboard.readImage) return;
    if (!s.images || !this.target) {
      // Pictures switched off, or the user left the AI app: the original goes back.
      this.restoreImageIfOurs(prefetched);
      return;
    }
    const image = prefetched ?? this.safeReadImage();
    if (!image || image.key === this.imageSwap?.maskedKey) return; // nothing there, or already ours
    const lines = this.readImageText(image).settled;
    if (lines) this.maskImage(image, lines, s, this.target);
    else void this.maskImageWhenRead(image);
  }

  private async maskImageWhenRead(image: ClipboardImage): Promise<void> {
    const lines = await this.readImageText(image);
    const s = this.deps.settings();
    const target = this.target;
    if (lines.length === 0 || !s.enabled || !s.images || this.paused || !target) return;
    // Only while the clipboard still holds this picture: a newer copy, or a
    // mask another call already painted, is left alone.
    const current = this.safeReadImage();
    if (!current || current.key !== image.key) return;
    this.maskImage(current, lines, s, target);
  }

  /** Paint out what the patterns, and any model answer already in, find. */
  private maskImage(image: ClipboardImage, lines: OcrLine[], s: ShieldSettings, target: AiTarget): void {
    const layout = layoutText(lines);
    const cached = this.cachedModelEntities(layout.text);
    const entities = cached
      ? resolveOverlaps([...this.patternEntities(layout.text, s), ...cached.filter((e) => s.kinds.has(e.kind))])
      : this.patternEntities(layout.text, s);
    if (!cached && this.deps.detectModel && layout.text) void this.upgradeImageWithModel(image, layout.text);
    const { boxes, placed } = entityBoxes(entities, layout);
    if (boxes.length === 0) return;
    const maskedKey = this.deps.clipboard.writeMaskedImage?.(image, boxes) ?? null;
    if (!maskedKey) return;
    this.imageSwap = { maskedKey, original: image };
    this.emit('masked', {
      target,
      count: placed.length,
      kinds: Array.from(new Set(placed.map((e) => e.kind))),
      invisibleRemoved: 0,
      imageKey: maskedKey,
    } satisfies MaskedEvent);
  }

  private async upgradeImageWithModel(image: ClipboardImage, text: string): Promise<void> {
    const found = await this.modelEntities(text);
    const s = this.deps.settings();
    const target = this.target;
    if (!s.enabled || !s.images || this.paused || !target) return;
    if (!found.some((e) => s.kinds.has(e.kind))) return;
    const lines = this.ocrCache.get(image.key)?.settled;
    if (!lines) return;
    // The clipboard must still hold this picture, or the pattern mask painted
    // on it; either way the repaint starts from the original.
    const current = this.safeReadImage();
    if (!current) return;
    const swap = this.imageSwap;
    if (swap && current.key === swap.maskedKey && swap.original.key === image.key) {
      this.maskImage(swap.original, lines, s, target);
    } else if (current.key === image.key) {
      this.maskImage(current, lines, s, target);
    }
  }

  private restoreImageIfOurs(prefetched?: ClipboardImage | null): void {
    const swap = this.imageSwap;
    if (!swap) return;
    this.imageSwap = null;
    const current = prefetched ?? this.safeReadImage();
    if (!current || current.key !== swap.maskedKey) return; // a newer copy: leave it
    this.deps.clipboard.writeImage?.(swap.original);
    this.emit('restored', { count: 0, via: 'snapshot', image: true } satisfies RestoredEvent);
  }

  /** Read each picture once; every later caller gets the same promise. */
  private readImageText(image: ClipboardImage): Settled<OcrLine[]> {
    const existing = this.ocrCache.get(image.key);
    if (existing) return existing;
    const recognize = this.deps.recognizeImage;
    const p = (recognize ? recognize(image) : Promise.resolve([] as OcrLine[])).then(
      (r) => r,
      (err) => {
        console.warn('[ai-shield] Reading a picture failed:', err?.message || err);
        return [] as OcrLine[];
      },
    ) as Settled<OcrLine[]>;
    void p.then((r) => {
      p.settled = r;
      // Warm the name model on the picture's text, as for copied text.
      if (r.length > 0 && !this.target) void this.modelEntities(layoutText(r).text);
    });
    this.ocrCache.set(image.key, p);
    if (this.ocrCache.size > OCR_CACHE_SIZE) {
      this.ocrCache.delete(this.ocrCache.keys().next().value as string);
    }
    return p;
  }

  private safeReadImage(): ClipboardImage | null {
    try {
      return this.deps.clipboard.readImage?.() ?? null;
    } catch {
      return null;
    }
  }

  private patternEntities(text: string, s: ShieldSettings): Entity[] {
    return detectEntities(text, { kinds: s.kinds, customTerms: s.customTerms });
  }

  private cachedModelEntities(text: string): Entity[] | null {
    const entry = this.modelCache.get(text) as (Promise<Entity[]> & { settled?: Entity[] }) | undefined;
    return entry?.settled ?? null;
  }

  private modelEntities(text: string): Promise<Entity[]> {
    if (!this.deps.detectModel) return Promise.resolve([]);
    const existing = this.modelCache.get(text);
    if (existing) return existing;
    const p = this.deps.detectModel(text).then(
      (r) => r,
      (err) => {
        console.warn('[ai-shield] Model detection failed:', err?.message || err);
        return [] as Entity[];
      },
    ) as Promise<Entity[]> & { settled?: Entity[] };
    p.then((r) => { p.settled = r; });
    this.modelCache.set(text, p);
    if (this.modelCache.size > MODEL_CACHE_SIZE) {
      this.modelCache.delete(this.modelCache.keys().next().value as string);
    }
    return p;
  }

  private safeRead(): string {
    try {
      return this.deps.clipboard.readText() || '';
    } catch {
      return '';
    }
  }
}
