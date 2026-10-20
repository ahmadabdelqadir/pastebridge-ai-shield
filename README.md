# @pastebridge/ai-shield

Masks secrets and personal data on the clipboard while an AI app is in front, and puts the real values back when you paste anywhere else.

You copy and paste as usual. Paste into ChatGPT and it receives `[EMAIL_1]` instead of `jane@acme.com`, and `[SECRET_1]` instead of your API key. Copy the answer, paste it into your mail client, and the placeholders turn back into the real values. Nothing is intercepted, no keystrokes are synthesized, and nothing leaves the machine.

This is the engine inside the [PasteBridge](https://pastebridge.com) Windows app, published on its own so the masking logic can be read, checked and reused.

## The invariant

The whole behaviour comes down to two lines, enforced on every foreground change and every copy:

- **An AI app is in front:** the clipboard holds the **masked** form. Sensitive values are replaced by placeholders.
- **Anything else is in front:** the clipboard holds the **real** form. Placeholders issued by this vault are replaced by the values they stand for.

Two rules keep it safe:

- **Never restore inside an AI app.** In an AI app the engine only ever masks. It restores nothing there, even a value the vault knows that would no longer be detected (a custom term the user just removed, a name the optional model found). Restoring inside the AI app is exactly the leak this exists to prevent.
- **Outside, touch only what is ours.** The clipboard is rewritten only when it holds placeholders from this vault, or the masked text the engine wrote itself. Ordinary clipboards are left alone.

If the user switches to an AI app and leaves without pasting, the original comes back whole, with its HTML and RTF formats. A newer copy is never overwritten by an older original.

## What it detects

Pattern detection always runs. It is deterministic and needs no model.

| Kind | What | Placeholder |
| --- | --- | --- |
| `PRIVATE_KEY` | PEM private key blocks, masked whole | `[PRIVATE_KEY_1]` |
| `SECRET` | Provider-shaped keys: OpenAI, Anthropic, Stripe, AWS access key IDs, GitHub, GitLab, Slack, Google, SendGrid, npm, Hugging Face, JWTs, Slack webhook URLs | `[SECRET_1]` |
| `SECRET` | `Bearer` / `Basic` / `Token` credentials (the scheme stays visible) | |
| `SECRET` | The password in `scheme://user:password@host` connection strings (only the password) | |
| `SECRET` | Secret-looking query parameters (`?api_key=`, `&token=`, `&sig=`, ...) | |
| `SECRET` | Assignments in code, config and `.env` files: `DB_PASSWORD="..."`, `"apiKey": "..."`, `password: ...`. Only the value is masked; the name stays so the model can still read the code. Values like `********`, `null`, `changeme`, `${VAR}` and `{{var}}` are skipped. | |
| `CARD` | 13 to 19 digits, Luhn-valid, starting with 2 to 6 | `[CARD_1]` |
| `IBAN` | IBANs that pass the mod-97 check | `[IBAN_1]` |
| `SSN` | US SSNs written with dashes. Nine bare digits are not matched. | `[SSN_1]` |
| `EMAIL` | Email addresses | `[EMAIL_1]` |
| `PHONE` | Numbers with an international prefix, or common grouped national formats, 9 to 15 digits. Bare digit runs, versions and dates are left alone. | `[PHONE_1]` |
| `IP` | Public IPv4 addresses. Private, loopback, link-local, CGNAT and multicast addresses are kept. | `[IP_1]` |
| `CUSTOM` | The user's own terms (client names, matters, project code names), case-insensitive, on word boundaries | `[REDACTED_1]` |
| `PERSON`, `ORG`, `LOCATION` | Only with the optional name model (see below) | `[PERSON_1]` |

When two matches overlap, the higher-priority kind wins (`PRIVATE_KEY`, `SECRET`, `CUSTOM`, `CARD`, `IBAN`, `SSN`, `EMAIL`, `PHONE`, `IP`, `PERSON`, `ORG`, `LOCATION`, in that order), then the longer span.

Invisible characters that models read but people cannot see are stripped from text before it reaches an AI app: Unicode tag characters (U+E0000 to U+E007F, used for "ASCII smuggling"), bidi embeddings, overrides and isolates, zero-width space, word joiner and invisible operators, a BOM inside text, and the Mongolian vowel separator. ZWJ and ZWNJ are kept because emoji sequences and several scripts need them. Detection runs after stripping, so a zero-width space cannot split a key in two and slip past the patterns.

### Optional name model

Patterns cannot find "Dana Levi" or "Northwind Trading". `ner.ts` adds an on-device pass with `Xenova/bert-base-NER` (quantized ONNX, about 110 MB, English) through [transformers.js](https://github.com/xenova/transformers.js). It is an optional peer dependency: install `@xenova/transformers` yourself if you want it. Importing this package never loads it.

The pattern mask goes on the clipboard at once. When the model answers, the mask is upgraded in place, but only while the clipboard still holds that text or the engine's own masked version of it. Greetings to the assistant ("Hi Claude") and code identifiers (`PaymentService`, `user_id`) are not treated as names.

## Which AI apps it recognises

`targets.ts` decides whether the foreground window is an AI app. Three signals, strongest first:

1. **Browser tab URL**, read through UI Automation by the Windows watcher. ChatGPT titles its tab after the conversation, so the URL is the reliable signal.
   ChatGPT (`chatgpt.com`, `chat.openai.com`), Claude (`claude.ai`), Gemini (`gemini.google.com`, `aistudio.google.com`), Copilot (`copilot.microsoft.com`, `m365.cloud.microsoft`), Perplexity, DeepSeek (`chat.deepseek.com`), Grok (`grok.com`, `x.com/i/grok`), Le Chat (`chat.mistral.ai`), Poe, Meta AI, NotebookLM, HuggingChat (`huggingface.co/chat`), Qwen (`chat.qwen.ai`), Kimi.
   Browsers checked: Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Arc, Zen, Chromium, Comet, Dia, Atlas. When the URL cannot be read, the window title is the fallback for ChatGPT, Claude, Gemini, Copilot, Perplexity and DeepSeek.
2. **Desktop app process:** ChatGPT, Claude, Copilot, Perplexity, Cursor, Windsurf, LM Studio, Ollama.
3. **Terminal window title:** Claude Code, Codex, Gemini CLI, Aider, opencode, Copilot CLI, in Windows Terminal, cmd, PowerShell, conhost, WezTerm, Alacritty, Tabby, Hyper and Warp. The title must start with the agent's name, so a shell whose title is a folder like `C:\src\claude-tools` does not count. VS Code is not a target: its title names the open file, not an agent.

Lookalike hosts (`notchatgpt.com`, `chatgpt.com.evil.example`) and non-HTTP URLs are rejected. Any target can be switched off (`disabledTargets`), and extra process names can be added (`extraProcesses`). `listTargets()` returns every built-in target for a settings screen.

## How the vault works

- **Memory only.** Originals are never written to disk.
- **Stable placeholders.** The same value gets the same placeholder for the life of the vault, so a conversation spread over several pastes stays coherent for the model. Emails, names and custom terms match case-insensitively; cards, phones and SSNs by their digits; IBANs without spaces.
- **TTL.** A mapping is forgotten 12 hours after it was last used (`ttlMs`). After that its placeholder is no longer restored.
- **Cap.** At most 5,000 values are held (`maxEntries`); the least recently used go first.
- **Counters.** Placeholders are numbered per label. `counterSnapshot()` returns the counters only, never originals, so they are safe to persist; pass them back as `counters` after a restart and `[EMAIL_1]` is never reissued for a different value. `clear()` forgets every original but keeps the counters for the same reason: an old conversation may still contain `[EMAIL_1]`.
- **Tolerant restore.** Models echo placeholders back in slightly different shapes. Restore accepts `[EMAIL_1]`, `EMAIL_1`, `<EMAIL_1>`, `{EMAIL_1}`, `\[EMAIL_1\]` and `[EMAIL 1]`, but only for labels the vault issues and only as whole tokens: `EMAIL_10` is never read as `EMAIL_1` followed by `0`.

## Usage

The package is named `@pastebridge/ai-shield`. Until it is published to npm, build it from this repository:

```sh
git clone https://github.com/ahmadabdelqadir/pastebridge-ai-shield
cd pastebridge-ai-shield
npm install
npm test
```

`AiShield` needs three things: a clipboard port, a vault and a settings getter. Here the clipboard is a variable:

```ts
import { AiShield, Vault, type ClipboardSnapshot, type EntityKind, type ShieldClipboard } from '@pastebridge/ai-shield';

// Any clipboard works if it implements ShieldClipboard. This one is a variable.
let clip: ClipboardSnapshot = { text: '' };
const clipboard: ShieldClipboard = {
  readText: () => clip.text,
  readSnapshot: () => ({ ...clip }),
  writeText: (text) => { clip = { text }; },
  writeSnapshot: (snapshot) => { clip = { ...snapshot }; },
};

const kinds = new Set<EntityKind>(['PRIVATE_KEY', 'SECRET', 'CARD', 'IBAN', 'SSN', 'EMAIL', 'PHONE', 'IP', 'CUSTOM']);

const shield = new AiShield({
  clipboard,
  vault: new Vault(),
  settings: () => ({
    enabled: true,
    kinds,
    customTerms: ['Project Falcon'],
    disabledTargets: new Set<string>(),
    extraProcesses: [],
    images: false,
  }),
});
shield.on('masked', (e) => console.log(`masked ${e.count} item(s) for ${e.target.name}`));
shield.on('restored', (e) => console.log(`restored ${e.count} placeholder(s)`));

// The user copies in Word. Nothing changes outside an AI app.
shield.onForeground({ process: 'WINWORD', title: 'Memo.docx - Word' });
clip = { text: 'Email jane@acme.com about Project Falcon', html: '<p>Email jane@acme.com about Project Falcon</p>' };
shield.onClipboardChanged();

// ChatGPT comes to the front: the clipboard now holds the masked text.
shield.onForeground({ process: 'chrome', title: 'New chat - Google Chrome', url: 'https://chatgpt.com/' });
console.log(clip.text); // Email [EMAIL_1] about [REDACTED_1]

// The user copies the answer inside ChatGPT: it stays masked there.
clip = { text: 'Sure. I will write to [EMAIL_1] about [REDACTED_1].' };
shield.onClipboardChanged();
console.log(clip.text); // Sure. I will write to [EMAIL_1] about [REDACTED_1].

// Outlook comes to the front: the placeholders turn back into the real values.
shield.onForeground({ process: 'OUTLOOK', title: 'Inbox - Outlook' });
console.log(clip.text); // Sure. I will write to jane@acme.com about Project Falcon.
```

In a real app, `writeText` and `writeSnapshot` write the system clipboard, and the owner must not treat those writes as user copies. On Windows, `ForegroundWatcher` supplies the two events:

```ts
import * as os from 'os';
import * as path from 'path';
import { ForegroundWatcher } from '@pastebridge/ai-shield';

const watcher = new ForegroundWatcher({ scriptDir: path.join(os.tmpdir(), 'ai-shield') });
watcher.on('foreground', (win) => shield.onForeground(win));
watcher.on('clipboard', () => shield.onClipboardChanged());
watcher.start(); // a no-op on other platforms
```

The watcher is one long-lived PowerShell process hosting a small C# loop. Every 100 ms it reads the foreground window and the clipboard sequence number and prints a line when either changes. It exits on its own when the parent process is gone.

Other controls: `pause(ms)` lets the real value through for a while (the original goes back on the clipboard first), `resume()`, `restoreIfOurs()` (call it on quit or when the user switches the shield off), and `forget()` with `vault.clear()` to drop everything held.

To add the name model:

```ts
import { detectWithModel, loadNerModel } from '@pastebridge/ai-shield';

await loadNerModel(cacheDir); // needs @xenova/transformers; downloads the model on first use
const shield = new AiShield({ clipboard, vault, settings, detectModel: detectWithModel });
```

### Pictures

A screenshot pasted into an AI app carries the same emails and keys as pasted text. `AiShield` handles pictures when the clipboard port implements `readImage`, `writeImage` and `writeMaskedImage`, and a `recognizeImage` function is supplied: the picture's text is read, the same detector finds the sensitive spans, and those spans are painted out of a copy with each box's average colour, which keeps nothing of the glyphs. The exact original picture comes back on leaving the AI app.

This package contains the pure parts: `layoutText` and `entityBoxes` (OCR words to text and back to pixel boxes), `paintBoxes` (the painting, on any 4-byte pixel order), and `prepareOcrImage`, `ocrScale` and `scaleLines` (enlarged grayscale input for Tesseract and mapping its boxes back). The OCR engine itself and the image clipboard are not included; see "What is not in this package".

## Limits

- **Pattern-based.** Detection is regular expressions with checksums where they exist, plus an optional English name model. It misses secrets with no recognisable shape and no `password=`-style context, names when the model is off, and formats not listed above. It can also mask things that are not sensitive.
- **Not a compliance tool.** It reduces what reaches an AI model. It is not a guarantee, not a certified DLP product, and not a HIPAA de-identification tool.
- **Pasted text and pictures only.** Typed text, drag and drop, and uploaded or attached files are not masked.
- **Pictures:** only text that OCR can read is found. Very small, rotated or handwritten text can slip through. A picture pasted immediately after copying it inside the AI app can arrive before OCR finishes, because nothing is touched until something is found.
- **Windows for app detection.** The foreground watcher uses PowerShell and UI Automation. Detection, the vault, target matching and the controller are plain TypeScript and run anywhere Node 18+ runs; on other platforms you supply the foreground events yourself.
- **Restore needs the same process.** The vault lives in memory. An answer copied after the app restarted, or after the 12-hour TTL, keeps its placeholders.

## What is not in this package

The PasteBridge app wraps this engine with code that depends on Electron or on the rest of the app, and that code stays there:

- the runtime that connects the engine to Electron's clipboard and `nativeImage`, settings, notifications and placeholder-counter persistence;
- the OCR module (Tesseract.js in a shared worker) and the worker-thread image reader built on it. `prepareOcrImage` is the function that reader runs in its worker;
- the settings screen and the model download UI.

## Layout

| File | Contents |
| --- | --- |
| `src/detect.ts` | Entity patterns, validators (Luhn, mod-97, public IPv4), overlap resolution, invisible-character stripping |
| `src/vault.ts` | Placeholder vault: mask, unmask, TTL, cap, counters |
| `src/targets.ts` | AI app matching by URL, process and window title |
| `src/shield.ts` | `AiShield`, the controller that enforces the invariant for text and pictures |
| `src/foreground.ts` | Windows foreground window and clipboard watcher (Node `child_process` only) |
| `src/ner.ts` | Optional name model adapter and token-to-span mapping |
| `src/image.ts` | Picture helpers: OCR layout, pixel boxes, painting, OCR input preparation |
| `src/ocr-types.ts` | The `OcrBox`, `OcrWord` and `OcrLine` shapes |
| `test/ai-shield.test.ts` | The test suite, no test framework needed |

## Development

```sh
npm install
npm test                          # tsc, then node dist/test/ai-shield.test.js
npx ts-node test/ai-shield.test.ts
```

Test values that look like credentials are assembled at runtime from pieces (`'ghp_' + 'A'.repeat(36)`), so no string in the repository looks like a real key to a secret scanner. Please keep it that way in new tests.

## License

MIT. See [LICENSE](LICENSE).
