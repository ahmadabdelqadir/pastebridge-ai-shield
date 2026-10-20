/**
 * @pastebridge/ai-shield — the masking engine inside the PasteBridge AI Shield.
 *
 * Importing this module never loads the optional name model: ner.ts requires
 * `@xenova/transformers` only when loadNerModel() is called.
 */

export * from './detect';
export * from './vault';
export * from './targets';
export * from './shield';
export * from './foreground';
export * from './ner';
export * from './image';
