// Run against the local site: npm run dev, then node scripts/test-certificate-gallery.mjs.
// Uses the installed Edge and Node DevTools client; no browser dependency needed.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const base = process.env.GALLERY_BASE ?? 'http://127.0.0.1:4321';
const manifest = JSON.parse(readFileSync(new URL('../src/content/achievements/certificate-gallery.json', import.meta.url), 'utf8'));
const evidence = process.env.GALLERY_SCREENSHOTS;
if (evidence) mkdirSync(evidence, { recursive: true });
const edge = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
assert.ok(edge, 'Microsoft Edge must be installed');
const port = 9335;
const browser = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-sync', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'gallery-test-'))}`, 'about:blank'], { windowsHide: true });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let socket;
let nextId = 0;
const pending = new Map();
const errors = [];
let checks = 0;

try {
  let target;
  for (let attempt = 0; attempt < 60 && !target; attempt++) {
    await sleep(100);
    try { target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json(); } catch { /* Edge is starting. */ }
  }
  assert.ok(target, 'Edge debugging connection failed');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve) => { socket.onopen = resolve; });
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const request = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) request?.reject(new Error(message.error.message));
      else request?.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') errors.push(message.params.entry.text);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    assert.ok(!result.exceptionDetails, result.exceptionDetails?.text);
    return result.result.value;
  };
  const check = (condition, message) => { assert.ok(condition, message); checks++; };
  const screenshot = async (name) => {
    if (!evidence) return;
    const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    writeFileSync(join(evidence, name), Buffer.from(data, 'base64'));
  };
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Debugger.enable');
  await send('Profiler.enable');
  await send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const [width, columns] of [[1440, 5], [1152, 3], [768, 2], [390, 1]]) {
    await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
    await send('Page.navigate', { url: `${base}/achievements/` });
    for (let attempt = 0; attempt < 80; attempt++) {
      await sleep(100);
      if (await evaluate(`document.readyState === 'complete' && location.pathname === '/achievements/'`)) break;
    }
    check(await evaluate(`document.title === 'Achievements | 0xG10D'`), 'Correct page title');
    check(await evaluate(`!!document.querySelector('[data-certificate-gallery]')`), 'Certificate gallery renders');
    const count = await evaluate(`document.querySelectorAll('[data-certificate-card]').length`);
    check(count > 0, 'Gallery contains audited previews');
    const rendered = await evaluate(`[...document.querySelectorAll('[data-certificate-card]')].map(card => ({ title: card.querySelector('h3').textContent.trim(), issuer: card.querySelector('[data-certificate-issuer]').textContent.trim(), date: card.querySelector('[data-certificate-date]').textContent.trim(), category: card.dataset.category, image: card.querySelector('img').getAttribute('src'), width: Number(card.querySelector('img').getAttribute('width')), height: Number(card.querySelector('img').getAttribute('height')) }))`);
    assert.deepEqual(rendered, manifest.map(({ title, issuer, date, category, image, width, height }) => ({ title, issuer, date: date ?? 'Date not stated', category, image, width, height })), 'Every card matches manifest title, issuer, date, category, image and dimensions');
    checks++;
    check(await evaluate(`Number(getComputedStyle(document.querySelector('.certificate-grid')).columnCount) === ${columns}`), `${width}px uses ${columns} masonry columns`);
    check(await evaluate(`document.documentElement.scrollWidth <= innerWidth`), `${width}px has no horizontal overflow`);
    check(await evaluate(`!document.querySelector('astro-error-overlay, vite-error-overlay')`), 'No framework overlay');
    check(await evaluate(`document.querySelector('.ctf-section') && document.querySelector('.roadmap-section')`), 'Existing CTF record and roadmap remain');
    check(await evaluate(`!document.querySelector('[data-certificate-gallery] a')`), 'No certificate links');
    check(await evaluate(`!document.querySelector('[data-certificate-gallery]').textContent.includes('Verified')`), 'No unsupported verification claim');
    check(await evaluate(`Promise.all([...document.querySelectorAll('[data-certificate-card] img')].map(async image => { image.loading = 'eager'; await image.decode(); return image.naturalWidth > 0 && getComputedStyle(image).objectFit === 'contain' && new URL(image.src).origin === location.origin; })).then(results => results.every(Boolean))`), 'All local previews load without cropping');
    check(await evaluate(`[...document.querySelectorAll('[data-certificate-card] img')].every(image => { const box = image.getBoundingClientRect(); const style = getComputedStyle(image); return Math.abs(box.height - box.width * image.naturalHeight / image.naturalWidth) < 2 && parseFloat(style.paddingTop) === 0 && parseFloat(style.paddingBottom) === 0; })`), 'Previews use natural image ratios without padded blank frames');
    check(await evaluate(`[...document.querySelectorAll('[data-certificate-card]')].every(card => { const content = card.querySelector('.certificate-preview').getBoundingClientRect().height + card.querySelector('.certificate-info').getBoundingClientRect().height; return Math.abs(card.getBoundingClientRect().height - content - 2) < 2; })`), 'Cards hug their content without stretched blank bottoms');
    check(await evaluate(`(() => { const columns = new Map(); for (const card of document.querySelectorAll('[data-certificate-card]')) { const box = card.getBoundingClientRect(); const key = Math.round(box.left); columns.set(key, [...(columns.get(key) ?? []), box]); } return [...columns.values()].every(cards => cards.sort((a, b) => a.top - b.top).every((card, index) => index === 0 || (card.top - cards[index - 1].bottom >= 0 && card.top - cards[index - 1].bottom <= 18))); })()`), 'Portrait and landscape cards stack without large column gaps');
    check(await evaluate(`getComputedStyle(document.querySelector('.preview-action')).position === 'absolute' && document.querySelector('.preview-action').getBoundingClientRect().height <= 36`), 'Expand control overlays the image without a separate bar');
    check(await evaluate(`parseFloat(getComputedStyle(document.querySelector('.certificate-info')).paddingTop) <= 14 && parseFloat(getComputedStyle(document.querySelector('.gallery-toolbar')).marginBottom) <= 16 && parseFloat(getComputedStyle(document.querySelector('.certificate-grid')).columnGap) <= 16`), 'Gallery metadata and gaps stay compact');
    check(await evaluate(`parseFloat(getComputedStyle(document.querySelector('.achievements-hero')).paddingTop) <= 32 && parseFloat(getComputedStyle(document.querySelector('.achievements-hero')).paddingBottom) <= 32 && parseFloat(getComputedStyle(document.querySelector('.certificates-section')).paddingTop) <= 24`), 'Hero and archive section use compact spacing');
    if (width < 640) {
      const firstPreviewTop = await evaluate(`document.querySelector('[data-certificate-open]').getBoundingClientRect().top`);
      check(firstPreviewTop <= 500, `Mobile shows certificate previews within the first viewport (${firstPreviewTop}px)`);
      await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
      await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
      check(await evaluate(`(() => { const filters = [...document.querySelectorAll('[data-certificate-filter]')]; const last = filters.at(-1); last.focus(); const box = last.getBoundingClientRect(); const strip = last.parentElement.getBoundingClientRect(); const style = getComputedStyle(last); const visible = box.left >= strip.left - 1 && box.right <= strip.right + 1; const ringInside = parseFloat(style.outlineOffset) <= -2 && parseFloat(style.outlineWidth) >= 2; filters[0].focus(); return visible && ringInside && document.documentElement.scrollWidth <= innerWidth; })()`), 'Keyboard focus reveals mobile filters with an unclipped inset focus ring and no page overflow');
    }
    await screenshot(`gallery-${width}.png`);
    await evaluate(`document.querySelector('[data-certificate-gallery]').scrollIntoView({ behavior: 'instant', block: 'start' }); window.scrollBy({ top: -90, behavior: 'instant' })`);
    await screenshot(`gallery-cards-${width}.png`);
    await evaluate(`(() => { const portrait = [...document.querySelectorAll('[data-certificate-card] img')].find(image => image.naturalHeight > image.naturalWidth); portrait?.closest('[data-certificate-card]').scrollIntoView({ behavior: 'instant', block: 'start' }); window.scrollBy({ top: -90, behavior: 'instant' }); })()`);
    await screenshot(`gallery-mixed-${width}.png`);
    await evaluate(`window.scrollTo({ top: 0, behavior: 'instant' })`);
    const categories = await evaluate(`[...document.querySelectorAll('[data-certificate-filter]')].map(button => button.dataset.certificateFilter)`);
    for (const category of categories) {
      const result = await evaluate(`(() => { const category = ${JSON.stringify(category)}; const button = [...document.querySelectorAll('[data-certificate-filter]')].find(item => item.dataset.certificateFilter === category); button.click(); const cards = [...document.querySelectorAll('[data-certificate-card]')]; const expected = cards.filter(card => category === 'All' || card.dataset.category === category).length; return { expected, visible: cards.filter(card => !card.hidden).length, pressed: button.getAttribute('aria-pressed'), selected: document.querySelectorAll('[data-certificate-filter][aria-pressed="true"]').length, status: document.querySelector('[data-certificate-count]').textContent, empty: !document.querySelector('[data-certificate-empty]').hidden }; })()`);
      check(result.expected === result.visible && result.pressed === 'true' && result.selected === 1, `${category} filter selects exact cards`);
      check(result.status.includes(String(result.expected)) && result.empty === (result.expected === 0), `${category} count and empty state agree`);
    }
    await evaluate(`document.querySelector('[data-certificate-filter="All"]').click(); document.querySelector('[data-certificate-open]').focus()`);
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r' });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
    check(await evaluate(`document.querySelector('dialog').open && document.activeElement === document.querySelector('[data-certificate-close]')`), 'Keyboard opens dialog and focuses Close');
    check(await evaluate(`document.querySelector('[data-certificate-dialog-title]').textContent === document.querySelector('[data-certificate-card] h3').textContent`), 'Dialog title matches card');
    check(await evaluate(`document.querySelector('[data-certificate-dialog-meta]').textContent === (() => { const card = document.querySelector('[data-certificate-card]'); return card.querySelector('[data-certificate-issuer]').textContent + ' · ' + card.querySelector('[data-certificate-date]').textContent + ' · ' + card.dataset.category; })()`), 'Dialog metadata matches card');
    check(await evaluate(`document.body.style.overflow === 'hidden'`), 'Dialog locks background scroll');
    await evaluate(`document.querySelector('[data-certificate-dialog-image]').decode()`);
    await screenshot(`gallery-lightbox-${width}.png`);
    for (let index = 0; index < 3; index++) await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
    check(await evaluate(`document.querySelector('dialog').contains(document.activeElement)`), 'Tab focus stays in modal');
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
    await sleep(50);
    check(await evaluate(`!document.querySelector('dialog').open && document.activeElement === document.querySelector('[data-certificate-open]') && document.body.style.overflow !== 'hidden'`), 'Escape closes, restores focus and scroll');
    await evaluate(`document.querySelector('[data-certificate-open]').click(); document.querySelector('[data-certificate-close]').click()`);
    check(await evaluate(`!document.querySelector('dialog').open`), 'Close button dismisses');
    await evaluate(`document.querySelector('[data-certificate-open]').click()`);
    await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: 1, y: 1, button: 'left', clickCount: 1 });
    await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: 1, y: 1, button: 'left', clickCount: 1 });
    check(await evaluate(`!document.querySelector('dialog').open`), 'Backdrop click dismisses');
  }
  const coverage = await send('Profiler.takePreciseCoverage');
  let coveredBytes = 0;
  let totalBytes = 0;
  for (const script of coverage.result) {
    if (!script.url.startsWith(base)) continue;
    const { scriptSource } = await send('Debugger.getScriptSource', { scriptId: script.scriptId });
    if (!scriptSource.includes('data-certificate-dialog-title') || !scriptSource.includes('data-certificate-open')) continue;
    const sourceLength = scriptSource.split('//# sourceMappingURL=')[0].length;
    const ranges = script.functions.flatMap((entry) => entry.ranges).map((range) => ({ ...range, endOffset: Math.min(range.endOffset, sourceLength) })).filter((range) => range.startOffset < range.endOffset);
    const boundaries = [...new Set(ranges.flatMap((range) => [range.startOffset, range.endOffset]))].sort((a, b) => a - b);
    for (let index = 0; index < boundaries.length - 1; index++) {
      const start = boundaries[index];
      const end = boundaries[index + 1];
      const active = ranges.filter((range) => range.startOffset <= start && range.endOffset >= end).sort((a, b) => (a.endOffset - a.startOffset) - (b.endOffset - b.startOffset));
      if (!active.length) continue;
      totalBytes += end - start;
      if (active[0].count > 0) coveredBytes += end - start;
    }
  }
  const percent = totalBytes ? 100 * coveredBytes / totalBytes : 0;
  if (evidence) writeFileSync(join(evidence, 'gallery-client-coverage.json'), JSON.stringify({ coveredBytes, totalBytes, percent }, null, 2));
  check(percent >= 80, `Gallery client executed byte coverage ${percent.toFixed(1)}% meets 80%`);
  await send('Profiler.stopPreciseCoverage');
  assert.deepEqual(errors, [], 'No browser runtime or resource errors');
  console.log(`PASS: ${checks} certificate gallery checks at 1440/1152/768/390px; client executed byte coverage ${percent.toFixed(1)}%; no browser errors.`);
} finally {
  socket?.close();
  browser.kill();
}
