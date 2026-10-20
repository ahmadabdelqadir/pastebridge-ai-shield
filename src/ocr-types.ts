/**
 * The shapes OCR results take, as image.ts and shield.ts consume them.
 *
 * In the PasteBridge app these come from its Tesseract module, which also
 * runs the recognition. That module is not part of this package: bring your
 * own OCR and convert its output to these shapes (Tesseract.js gives lines,
 * words and per-symbol boxes that map onto them directly).
 */

/** A rectangle in image pixels. */
export interface OcrBox {
  x0: number;
  y0: number;
  /** Exclusive. */
  x1: number;
  /** Exclusive. */
  y1: number;
}

export interface OcrWord {
  text: string;
  box: OcrBox;
  /** One box per UTF-16 unit of `text`, when Tesseract's symbols line up with it. */
  chars?: OcrBox[];
}

export interface OcrLine {
  words: OcrWord[];
}
