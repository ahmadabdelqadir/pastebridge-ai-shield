/**
 * AI Shield — foreground window and clipboard-sequence watcher (Windows).
 *
 * One long-lived PowerShell process hosts a small C# loop. Every 100 ms it
 * reads the foreground window (process, title) and the clipboard sequence
 * number, and prints a JSON line when either changes. When the foreground app
 * is a browser it also reads the active tab's URL through UI Automation; that
 * is what tells chatgpt.com apart from any other tab, because ChatGPT titles
 * its tab after the conversation, not after itself.
 *
 * One process for the app's lifetime — never one spawn per poll — keeps the
 * cost to a sleeping thread. The loop exits on its own when the parent
 * process is gone, so a crashed app cannot leave it behind.
 */

import { spawn, type ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as path from 'path';
import { BROWSER_PROCESSES, type ForegroundWindow } from './targets';

const SCRIPT_NAME = 'ai-shield-watch.ps1';

function buildScript(parentPid: number): string {
  const browsers = [...BROWSER_PROCESSES].map((b) => `"${b}"`).join(', ');
  return `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -ReferencedAssemblies UIAutomationClient, UIAutomationTypes -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Automation;

public static class ShieldWatch {
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();

    static string Esc(string s) {
        if (s == null) return "";
        var sb = new StringBuilder(s.Length + 8);
        foreach (char c in s) {
            if (c == '"' || c == '\\\\') { sb.Append('\\\\'); sb.Append(c); }
            else if (c < 0x20) sb.Append("\\\\u" + ((int)c).ToString("x4"));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    static string ValueOf(AutomationElement el) {
        if (el == null) return "";
        object pattern;
        if (el.TryGetCurrentPattern(ValuePattern.Pattern, out pattern)) {
            return ((ValuePattern)pattern).Current.Value ?? "";
        }
        return "";
    }

    // The address bar first: it is part of the browser's own UI, so reading it
    // does not make the browser build accessibility trees for web pages (which
    // costs it CPU on every page). The page document is the fallback.
    static string ReadUrl(IntPtr hwnd) {
        try {
            var root = AutomationElement.FromHandle(hwnd);
            var edit = root.FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit));
            string url = ValueOf(edit);
            if (url.Length > 0) return url;
            var doc = root.FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Document));
            return ValueOf(doc);
        } catch { }
        return "";
    }

    public static void Run(int parentPid, string[] browsers) {
        var browserSet = new HashSet<string>(browsers, StringComparer.OrdinalIgnoreCase);
        var names = new Dictionary<uint, string>();
        IntPtr lastHwnd = IntPtr.Zero;
        string lastTitle = null;
        uint lastSeq = GetClipboardSequenceNumber();
        var sb = new StringBuilder(512);
        var parentCheck = Stopwatch.StartNew();
        while (true) {
            if (parentCheck.ElapsedMilliseconds > 2000) {
                parentCheck.Restart();
                try { using (var p = Process.GetProcessById(parentPid)) { if (p.HasExited) return; } }
                catch { return; }
            }
            IntPtr hwnd = GetForegroundWindow();
            sb.Clear();
            GetWindowTextW(hwnd, sb, sb.Capacity);
            string title = sb.ToString();
            if (hwnd != lastHwnd || title != lastTitle) {
                lastHwnd = hwnd;
                lastTitle = title;
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                string name;
                if (!names.TryGetValue(pid, out name)) {
                    try { using (var p = Process.GetProcessById((int)pid)) { name = p.ProcessName; } }
                    catch { name = ""; }
                    if (names.Count > 256) names.Clear();
                    names[pid] = name;
                }
                string url = browserSet.Contains(name) ? ReadUrl(hwnd) : "";
                Console.WriteLine("{\\"t\\":\\"fg\\",\\"process\\":\\"" + Esc(name) + "\\",\\"title\\":\\"" + Esc(title) + "\\",\\"url\\":\\"" + Esc(url) + "\\"}");
                Console.Out.Flush();
            }
            uint seq = GetClipboardSequenceNumber();
            if (seq != lastSeq) {
                lastSeq = seq;
                Console.WriteLine("{\\"t\\":\\"clip\\",\\"seq\\":" + seq + "}");
                Console.Out.Flush();
            }
            Thread.Sleep(100);
        }
    }
}
'@
[ShieldWatch]::Run(${parentPid}, @(${browsers}))
`;
}

export type WatchEvent =
  | { t: 'fg'; window: ForegroundWindow }
  | { t: 'clip'; seq: number };

/** Parse one helper output line. Exported for tests. */
export function parseWatchLine(line: string): WatchEvent | null {
  let raw: any;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  if (raw.t === 'fg' && typeof raw.process === 'string' && typeof raw.title === 'string') {
    const url = typeof raw.url === 'string' && raw.url ? raw.url : undefined;
    return { t: 'fg', window: { process: raw.process, title: raw.title, url } };
  }
  if (raw.t === 'clip' && Number.isSafeInteger(raw.seq)) {
    return { t: 'clip', seq: raw.seq };
  }
  return null;
}

export interface ForegroundWatcherOptions {
  scriptDir: string;
  /** Restart delay after the helper dies; doubles up to 60 s. */
  baseRestartMs?: number;
}

/**
 * Emits 'foreground' (ForegroundWindow) and 'clipboard' (sequence number).
 * A no-op on platforms other than Windows.
 */
export class ForegroundWatcher extends EventEmitter {
  private child: ChildProcess | null = null;
  private stopped = true;
  private restartMs: number;
  private restartTimer: ReturnType<typeof setTimeout> | null = null;
  private buffer = '';

  constructor(private readonly opts: ForegroundWatcherOptions) {
    super();
    this.restartMs = opts.baseRestartMs ?? 1000;
  }

  get running(): boolean {
    return this.child !== null;
  }

  start(): void {
    if (process.platform !== 'win32' || !this.stopped) return;
    this.stopped = false;
    this.launch();
  }

  stop(): void {
    this.stopped = true;
    if (this.restartTimer) clearTimeout(this.restartTimer);
    this.restartTimer = null;
    const child = this.child;
    this.child = null;
    if (child && child.exitCode === null) child.kill();
  }

  private launch(): void {
    let scriptPath: string;
    try {
      fs.mkdirSync(this.opts.scriptDir, { recursive: true });
      scriptPath = path.join(this.opts.scriptDir, SCRIPT_NAME);
      fs.writeFileSync(scriptPath, buildScript(process.pid), 'utf8');
    } catch (err: any) {
      console.error('[ai-shield] Could not stage watcher script:', err.message);
      this.scheduleRestart();
      return;
    }

    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-File', scriptPath],
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    this.child = child;
    this.buffer = '';
    const startedAt = Date.now();

    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => this.onData(chunk));
    let stderr = '';
    child.stderr?.on('data', (d: Buffer) => {
      if (stderr.length < 4000) stderr += d.toString();
    });
    // A failed spawn (blocked or missing powershell.exe) emits 'error' and may
    // never emit 'exit': release the handle and retry here too, or the app
    // would report a watcher that is not running and never mask anything.
    child.on('error', (err) => {
      console.error('[ai-shield] Watcher failed to start:', err.message);
      if (this.child !== child) return;
      this.child = null;
      this.scheduleRestart();
    });
    child.on('exit', (code) => {
      if (this.child === child) this.child = null;
      if (this.stopped) return;
      console.warn(`[ai-shield] Watcher exited (code=${code})${stderr ? `: ${stderr.trim().slice(0, 500)}` : ''}`);
      // A helper that lived a while gets a fast restart; one that keeps dying
      // backs off so a broken PowerShell does not spin.
      if (Date.now() - startedAt > 60_000) this.restartMs = this.opts.baseRestartMs ?? 1000;
      this.scheduleRestart();
    });
  }

  private scheduleRestart(): void {
    if (this.stopped || this.restartTimer) return;
    const delay = this.restartMs;
    this.restartMs = Math.min(this.restartMs * 2, 60_000);
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      if (!this.stopped) this.launch();
    }, delay);
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    if (this.buffer.length > 1_000_000) this.buffer = this.buffer.slice(-100_000);
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;
      const event = parseWatchLine(line);
      if (!event) continue;
      if (event.t === 'fg') this.emit('foreground', event.window);
      else this.emit('clipboard', event.seq);
    }
  }
}
