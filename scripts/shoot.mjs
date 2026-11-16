#!/usr/bin/env node
// Visual QA helper: full-page screenshots of the local dev server at 1440, 768 and 390px.
// Usage: node scripts/shoot.mjs home= blog=blog/ ...
// Drives an installed Edge over the DevTools protocol, so no extra npm dependency is needed.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const base = process.env.SHOOT_BASE ?? 'http://localhost:4321';
const out = process.env.SHOOT_OUT ?? 'docs/redesign/shots';
const widths = (process.env.SHOOT_WIDTHS ?? '1440,768,390').split(',').map(Number);
const edge = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
if (!edge) throw new Error('Edge not found');
mkdirSync(out, { recursive: true });

const port = 9333;
const browser = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-sync', '--guest', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'shoot-'))}`, 'about:blank']);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let target;
for (let i = 0; i < 40 && !target; i++) {
  await sleep(250);
  try {
    // Open our own tab: Edge may show first-run or sync pages in the default one.
    target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
  } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pending = new Map();
const errors = [];
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id) pending.get(msg.id)?.(msg.result);
  if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
  if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') errors.push(`${msg.params.entry.text} ${msg.params.entry.url ?? ''}`);
};
const send = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });

await send('Page.enable');
await send('Runtime.enable');
await send('Log.enable');

for (const arg of process.argv.slice(2)) {
  // Paths are given without the leading slash (Git Bash rewrites '/x' arguments): home= blog=blog/
  const [name, raw = ''] = arg.split('=');
  const path = '/' + raw.replace(/^\/+/, '');
  for (const width of widths) {
    errors.length = 0;
    await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
    await send('Page.navigate', { url: base + path });
    for (let i = 0; i < 60; i++) {
      await sleep(250);
      const ready = await send('Runtime.evaluate', { expression: 'document.readyState + location.pathname' });
      if (ready.result.value === 'complete' + path.split(/[?#]/)[0]) break;
    }
    await sleep(900);
    const { result } = await send('Runtime.evaluate', {
      expression: 'JSON.stringify({href: location.href, title: document.title, h: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight, document.querySelector(".page-wrapper")?.scrollHeight ?? 0), overflow: (document.body.style.overflowX = "visible", document.documentElement.scrollWidth - document.documentElement.clientWidth)})'
    });
    const { h, overflow, href, title } = JSON.parse(result.value); if (process.env.SHOOT_DEBUG) console.log(href, title);
    await send('Emulation.setDeviceMetricsOverride', { width, height: Math.min(h, 6000), deviceScaleFactor: 1, mobile: width < 500 });
    await sleep(500);
    const { data } = await send('Page.captureScreenshot', { format: 'webp', quality: 80 });
    writeFileSync(`${out}/${name}-${width}.webp`, Buffer.from(data, 'base64'));
    console.log(`${name}-${width}.webp height=${h} x-overflow=${overflow} errors=${errors.length}${errors.length ? ' ' + errors.join(' | ') : ''}`);
  }
}
ws.close();
browser.kill();
