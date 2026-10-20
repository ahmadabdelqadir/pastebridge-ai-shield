/**
 * AI Shield — pictures.
 *
 * A screenshot pasted into an AI app carries the same emails and keys as
 * pasted text, so a picture gets the same treatment: its text is read on this
 * PC, the same detector finds the sensitive spans, and those spans are painted
 * out of the picture before the AI app can receive it.
 *
 * Pure module: no Electron, no I/O. OCR and the clipboard live in the runtime;
 * this file turns OCR words into text, maps detected spans back to pixels,
 * paints the boxes, and prepares the grayscale image Tesseract reads best.
 */

import type { OcrBox, OcrLine, OcrWord } from './ocr-types';
import type { Entity } from './detect';

export type { OcrBox, OcrLine, OcrWord } from './ocr-types';

export interface ImageLayout {
  /** Words joined by spaces, lines by newlines: what the detector reads. */
  text: string;
  /** Where each word sits in `text`. */
  words: Array<{ start: number; end: number; line: number; word: OcrWord }>;
}

export function layoutText(lines: readonly OcrLine[]): ImageLayout {
  const words: ImageLayout['words'] = [];
  let text = '';
  lines.forEach((line, li) => {
    if (li > 0) text += '\n';
    line.words.forEach((word, wi) => {
      if (wi > 0) text += ' ';
      words.push({ start: text.length, end: text.length + word.text.length, line: li, word });
      text += word.text;
    });
  });
  return { text, words };
}

function union(a: OcrBox | null, b: OcrBox): OcrBox {
  if (!a) return { ...b };
  return { x0: Math.min(a.x0, b.x0), y0: Math.min(a.y0, b.y0), x1: Math.max(a.x1, b.x1), y1: Math.max(a.y1, b.y1) };
}

/**
 * The pixels to paint for each entity: one box per line it touches, covering
 * the characters it spans (the whole word when OCR gave no character boxes),
 * padded so anti-aliased edges go too. Entities that touch no word are
 * dropped; `placed` is what will actually be hidden.
 */
export function entityBoxes(entities: readonly Entity[], layout: ImageLayout): { boxes: OcrBox[]; placed: Entity[] } {
  const boxes: OcrBox[] = [];
  const placed: Entity[] = [];
  for (const e of entities) {
    const perLine = new Map<number, OcrBox>();
    for (const w of layout.words) {
      if (w.end <= e.start || w.start >= e.end) continue;
      const from = Math.max(0, e.start - w.start);
      const to = Math.min(w.word.text.length, e.end - w.start);
      let box: OcrBox;
      const chars = w.word.chars;
      if (chars && chars.length === w.word.text.length && (from > 0 || to < chars.length)) {
        let span: OcrBox | null = null;
        for (let i = from; i < to; i++) span = union(span, chars[i]);
        // Full word height: a span of short letters must not leave the tops of
        // its neighbours' ascenders behind.
        box = { x0: span!.x0, y0: w.word.box.y0, x1: span!.x1, y1: w.word.box.y1 };
      } else {
        box = w.word.box;
      }
      perLine.set(w.line, union(perLine.get(w.line) ?? null, box));
    }
    if (perLine.size === 0) continue;
    placed.push(e);
    for (const b of perLine.values()) {
      const pad = Math.max(2, Math.round((b.y1 - b.y0) * 0.2));
      boxes.push({ x0: b.x0 - pad, y0: b.y0 - pad, x1: b.x1 + pad, y1: b.y1 + pad });
    }
  }
  return { boxes, placed };
}

/**
 * Paint each box with its own average colour: it reads as a heavy blur, but
 * unlike a real blur or a pixelation it keeps nothing of the glyphs, so the
 * text cannot be recovered from it. Works on any 4-byte pixel order. Boxes are
 * clipped to the picture; returns how many were painted.
 */
export function paintBoxes(pixels: Uint8Array, width: number, height: number, boxes: readonly OcrBox[]): number {
  let painted = 0;
  for (const b of boxes) {
    const x0 = Math.max(0, Math.floor(b.x0));
    const y0 = Math.max(0, Math.floor(b.y0));
    const x1 = Math.min(width, Math.ceil(b.x1));
    const y1 = Math.min(height, Math.ceil(b.y1));
    if (x1 <= x0 || y1 <= y0) continue;
    const sum = [0, 0, 0, 0];
    for (let y = y0; y < y1; y++) {
      for (let i = (y * width + x0) * 4, end = (y * width + x1) * 4; i < end; i += 4) {
        sum[0] += pixels[i];
        sum[1] += pixels[i + 1];
        sum[2] += pixels[i + 2];
        sum[3] += pixels[i + 3];
      }
    }
    const n = (x1 - x0) * (y1 - y0);
    const mean = sum.map((v) => Math.round(v / n));
    for (let y = y0; y < y1; y++) {
      for (let i = (y * width + x0) * 4, end = (y * width + x1) * 4; i < end; i += 4) {
        pixels[i] = mean[0];
        pixels[i + 1] = mean[1];
        pixels[i + 2] = mean[2];
        pixels[i + 3] = mean[3];
      }
    }
    painted++;
  }
  return painted;
}

/** Pictures bigger than this are not read at all (an 8K screen is 33 MP). */
export const MAX_OCR_PIXELS = 40_000_000;

/**
 * How much to enlarge a picture before OCR. Screen text is 12–16 px tall and
 * Tesseract drops small marks at that size (the dot in an email address), so
 * pictures up to a 2560×1600 screen are read at twice their size. Larger ones
 * are read as they are, to keep the worker's time and memory bounded.
 */
export function ocrScale(width: number, height: number): number {
  return width * height <= 2560 * 1640 ? 2 : 1;
}

/** Map OCR results from an enlarged picture back to its own pixels. */
export function scaleLines(lines: readonly OcrLine[], factor: number): OcrLine[] {
  if (factor === 1) return lines as OcrLine[];
  const s = (b: OcrBox): OcrBox => ({
    x0: Math.floor(b.x0 * factor),
    y0: Math.floor(b.y0 * factor),
    x1: Math.ceil(b.x1 * factor),
    y1: Math.ceil(b.y1 * factor),
  });
  return lines.map((l) => ({
    words: l.words.map((w) => (w.chars ? { text: w.text, box: s(w.box), chars: w.chars.map(s) } : { text: w.text, box: s(w.box) })),
  }));
}

/**
 * Turn 32-bit premultiplied BGRA pixels (what Electron's toBitmap gives on
 * Windows) into an 8-bit grayscale PGM, enlarged `scale` times with bilinear
 * filtering. Transparent areas come out white, so dark text on a transparent
 * background stays readable. PGM needs no compression, so this is cheap, and
 * Tesseract reads it directly.
 *
 * Self-contained on purpose (no outside references): the runtime runs its
 * source in a worker thread so a full-screen picture never stalls the app.
 */
export function prepareOcrImage(pixels: Uint8Array, width: number, height: number, scale: number): Uint8Array {
  const gray = new Uint8Array(width * height);
  for (let i = 0, p = 0; i < gray.length; i++, p += 4) {
    // Premultiplied: composite over white by adding the missing coverage.
    const g = ((pixels[p] * 29 + pixels[p + 1] * 150 + pixels[p + 2] * 77) >> 8) + (255 - pixels[p + 3]);
    gray[i] = g > 255 ? 255 : g;
  }
  const W = width * scale;
  const H = height * scale;
  const header = `P5\n${W} ${H}\n255\n`;
  const out = new Uint8Array(header.length + W * H);
  for (let i = 0; i < header.length; i++) out[i] = header.charCodeAt(i);
  const base = header.length;
  if (scale === 1) {
    out.set(gray, base);
    return out;
  }
  for (let y = 0; y < H; y++) {
    const sy = Math.max(0, (y + 0.5) / scale - 0.5);
    const y0 = Math.floor(sy);
    const y1 = y0 + 1 < height ? y0 + 1 : height - 1;
    const fy = sy - y0;
    const r0 = y0 * width;
    const r1 = y1 * width;
    const row = base + y * W;
    for (let x = 0; x < W; x++) {
      const sx = Math.max(0, (x + 0.5) / scale - 0.5);
      const x0 = Math.floor(sx);
      const x1 = x0 + 1 < width ? x0 + 1 : width - 1;
      const fx = sx - x0;
      const top = gray[r0 + x0] + (gray[r0 + x1] - gray[r0 + x0]) * fx;
      const bottom = gray[r1 + x0] + (gray[r1 + x1] - gray[r1 + x0]) * fx;
      out[row + x] = Math.round(top + (bottom - top) * fy);
    }
  }
  return out;
}
