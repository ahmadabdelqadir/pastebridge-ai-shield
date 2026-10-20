/**
 * AI Shield — which foreground windows count as "an AI is about to read this".
 *
 * Three signals, strongest first:
 *   1. The browser tab's URL (read through UI Automation by the watcher).
 *   2. The process: dedicated AI desktop apps.
 *   3. The window title: terminals running a coding agent set it, and it is
 *      the fallback when a browser's URL cannot be read.
 *
 * Pure module so the matching can be tested without a desktop.
 */

export interface ForegroundWindow {
  /** Executable name without extension, any case: "chrome", "ChatGPT". */
  process: string;
  title: string;
  /** Active tab URL when the foreground app is a browser and it was readable. */
  url?: string;
}

export interface AiTarget {
  id: string;
  name: string;
}

interface HostRule extends AiTarget {
  hosts: string[];
  /** Optional path prefix, for AI apps that share a host with other products. */
  path?: string;
}

const HOST_RULES: HostRule[] = [
  { id: 'chatgpt', name: 'ChatGPT', hosts: ['chatgpt.com', 'chat.openai.com'] },
  { id: 'claude', name: 'Claude', hosts: ['claude.ai'] },
  { id: 'gemini', name: 'Gemini', hosts: ['gemini.google.com', 'aistudio.google.com'] },
  { id: 'copilot', name: 'Copilot', hosts: ['copilot.microsoft.com', 'm365.cloud.microsoft'] },
  { id: 'perplexity', name: 'Perplexity', hosts: ['perplexity.ai', 'www.perplexity.ai'] },
  { id: 'deepseek', name: 'DeepSeek', hosts: ['chat.deepseek.com'] },
  { id: 'grok', name: 'Grok', hosts: ['grok.com'] },
  { id: 'grok', name: 'Grok', hosts: ['x.com'], path: '/i/grok' },
  { id: 'mistral', name: 'Le Chat', hosts: ['chat.mistral.ai'] },
  { id: 'poe', name: 'Poe', hosts: ['poe.com'] },
  { id: 'meta-ai', name: 'Meta AI', hosts: ['www.meta.ai', 'meta.ai'] },
  { id: 'notebooklm', name: 'NotebookLM', hosts: ['notebooklm.google.com'] },
  { id: 'huggingchat', name: 'HuggingChat', hosts: ['huggingface.co'], path: '/chat' },
  { id: 'qwen', name: 'Qwen', hosts: ['chat.qwen.ai'] },
  { id: 'kimi', name: 'Kimi', hosts: ['kimi.com', 'www.kimi.com'] },
];

const PROCESS_RULES: Record<string, AiTarget> = {
  chatgpt: { id: 'chatgpt', name: 'ChatGPT' },
  claude: { id: 'claude', name: 'Claude' },
  'ms-copilot': { id: 'copilot', name: 'Copilot' },
  copilot: { id: 'copilot', name: 'Copilot' },
  perplexity: { id: 'perplexity', name: 'Perplexity' },
  cursor: { id: 'cursor', name: 'Cursor' },
  windsurf: { id: 'windsurf', name: 'Windsurf' },
  'lm studio': { id: 'lm-studio', name: 'LM Studio' },
  ollama: { id: 'ollama', name: 'Ollama' },
};

export const BROWSER_PROCESSES = new Set([
  'chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'arc', 'zen', 'chromium', 'comet', 'dia', 'atlas',
]);

const TERMINAL_PROCESSES = new Set([
  'windowsterminal', 'wt', 'cmd', 'powershell', 'pwsh', 'conhost', 'wezterm-gui', 'alacritty', 'tabby', 'hyper', 'warp',
]);

/**
 * Coding agents that run in a terminal, matched against the window title the
 * agent sets (Claude Code's "✳ task") or the command name at its start.
 * Anchored at the start on purpose: a plain shell's title is usually its
 * working directory, and "C:\src\claude-tools" must not turn every paste into
 * that shell into placeholders. VS Code is deliberately absent: its title
 * names the open file and project, not an agent.
 */
const TERMINAL_AGENT_TITLES: Array<{ pattern: RegExp; target: AiTarget }> = [
  { pattern: /^(?:✳|claude(?: code)?\b)/i, target: { id: 'claude-code', name: 'Claude Code' } },
  { pattern: /^codex\b/i, target: { id: 'codex', name: 'Codex' } },
  { pattern: /^gemini\b/i, target: { id: 'gemini-cli', name: 'Gemini CLI' } },
  { pattern: /^aider\b/i, target: { id: 'aider', name: 'Aider' } },
  { pattern: /^opencode\b/i, target: { id: 'opencode', name: 'opencode' } },
  { pattern: /^copilot\b/i, target: { id: 'copilot-cli', name: 'Copilot CLI' } },
];

/** Title fallbacks for browsers whose URL could not be read. */
const BROWSER_TITLE_RULES: Array<{ pattern: RegExp; target: AiTarget }> = [
  { pattern: /(?:^|[-–—|] )ChatGPT(?: [-–—|]|$)/, target: { id: 'chatgpt', name: 'ChatGPT' } },
  { pattern: /(?:^|[-–—|] )Claude(?: [-–—|]|$)/, target: { id: 'claude', name: 'Claude' } },
  { pattern: /(?:^|[-–—|] )(?:Google )?Gemini(?: [-–—|]|$)/, target: { id: 'gemini', name: 'Gemini' } },
  { pattern: /(?:^|[-–—|] )(?:Microsoft )?Copilot(?: [-–—|]|$)/, target: { id: 'copilot', name: 'Copilot' } },
  { pattern: /(?:^|[-–—|] )Perplexity(?: [-–—|]|$)/, target: { id: 'perplexity', name: 'Perplexity' } },
  { pattern: /(?:^|[-–—|] )DeepSeek(?: [-–—|]|$)/, target: { id: 'deepseek', name: 'DeepSeek' } },
];

export interface TargetListing extends AiTarget {
  group: 'web' | 'desktop' | 'terminal';
}

/** Every built-in target once, for the settings screen's per-app switches. */
export function listTargets(): TargetListing[] {
  const seen = new Set<string>();
  const out: TargetListing[] = [];
  const add = (t: AiTarget, group: TargetListing['group']) => {
    if (seen.has(t.id)) return;
    seen.add(t.id);
    out.push({ id: t.id, name: t.name, group });
  };
  for (const r of HOST_RULES) add(r, 'web');
  for (const t of Object.values(PROCESS_RULES)) add(t, 'desktop');
  for (const r of TERMINAL_AGENT_TITLES) add(r.target, 'terminal');
  return out;
}

function processKey(name: string): string {
  return name.toLowerCase().replace(/\.exe$/, '');
}

export function matchUrl(url: string): AiTarget | null {
  let parsed: URL;
  try {
    parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  const host = parsed.hostname.toLowerCase();
  for (const rule of HOST_RULES) {
    const hostOk = rule.hosts.some((h) => host === h || host.endsWith(`.${h}`));
    if (!hostOk) continue;
    if (rule.path && !parsed.pathname.startsWith(rule.path)) continue;
    return { id: rule.id, name: rule.name };
  }
  return null;
}

export interface MatchOptions {
  /** Target ids the user switched off. */
  disabled?: ReadonlySet<string>;
  /** Extra process names (no .exe) the user marked as AI apps. */
  extraProcesses?: readonly string[];
}

export function matchAiTarget(win: ForegroundWindow, opts: MatchOptions = {}): AiTarget | null {
  const target = matchRaw(win, opts);
  if (!target || opts.disabled?.has(target.id)) return null;
  return target;
}

function matchRaw(win: ForegroundWindow, opts: MatchOptions): AiTarget | null {
  const proc = processKey(win.process || '');
  if (!proc) return null;

  if (BROWSER_PROCESSES.has(proc)) {
    if (win.url) return matchUrl(win.url);
    for (const rule of BROWSER_TITLE_RULES) {
      if (rule.pattern.test(win.title)) return rule.target;
    }
    return null;
  }

  const app = PROCESS_RULES[proc];
  if (app) return app;

  if (opts.extraProcesses?.some((p) => processKey(p) === proc)) {
    return { id: `custom:${proc}`, name: win.process };
  }

  if (TERMINAL_PROCESSES.has(proc)) {
    for (const rule of TERMINAL_AGENT_TITLES) {
      if (rule.pattern.test(win.title)) return rule.target;
    }
  }
  return null;
}
