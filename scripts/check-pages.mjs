#!/usr/bin/env node
// Regression sweep: loads every built page from the production preview (port 4322) at 390 and 2560px
// and reports horizontal overflow, console errors, broken images and missing <h1>.
// Usage: npm run build && npx astro preview --port 4322   then   node scripts/check-pages.mjs
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

const base = 'http://localhost:4322';
const edge = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
const walk = (dir, out = []) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name === 'index.html') out.push('/' + relative('dist', dir).replaceAll('\\', '/') + '/');
  }
  return out;
};
const pages = walk('dist').map((p) => (p === '//' ? '/' : p));

const port = 9333;
const browser = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-sync', '--guest', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'check-'))}`, 'about:blank']);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 80 && !target; i++) {
  await sleep(250);
  try {
    target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
  } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pending = new Map();
let errors = [];
let loaded = () => {};
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id) pending.get(msg.id)?.(msg.result);
  if (msg.method === 'Page.loadEventFired') loaded();
  if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
  if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') errors.push(`${msg.params.entry.text} ${msg.params.entry.url ?? ''}`);
};
const send = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
await send('Page.enable');
await send('Runtime.enable');
await send('Log.enable');

const probe = `JSON.stringify({
  overflow: (document.body.style.overflowX = 'visible', document.documentElement.scrollWidth - document.documentElement.clientWidth),
  h1: document.querySelectorAll('h1').length,
  redirect: !!document.querySelector('meta[http-equiv=refresh]'),
  brokenImages: [...document.images].filter((img) => img.complete && img.naturalWidth === 0 && img.loading !== 'lazy').map((img) => img.getAttribute('src'))
})`;

const failures = [];
let checked = 0;
for (const width of [390, 2560]) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
  for (const page of pages) {
    errors = [];
    const done = new Promise((r) => (loaded = r));
    await send('Page.navigate', { url: base + page });
    await Promise.race([done, sleep(8000)]);
    await sleep(120);
    const { result } = await send('Runtime.evaluate', { expression: probe });
    const info = JSON.parse(result?.value ?? '{}');
    checked++;
    if (info.redirect) continue; // legacy short-slug redirect stubs have no layout
    const problems = [];
    if (info.overflow > 0) problems.push(`overflow ${info.overflow}px`);
    if (info.h1 !== 1) problems.push(`h1 count ${info.h1}`);
    if (info.brokenImages?.length) problems.push(`broken images ${info.brokenImages.join(', ')}`);
    if (errors.length) problems.push(`console: ${[...new Set(errors)].join(' | ')}`);
    if (problems.length) failures.push(`${width}px ${page} -> ${problems.join('; ')}`);
  }
}
console.log(`pages ${pages.length}, loads ${checked}, failures ${failures.length}`);
failures.forEach((f) => console.log(f));
ws.close();
browser.kill();
