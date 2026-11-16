# 0xG10D redesign report

Updated: 2026-11-16. Branch: `redesign/monochrome`. Rollback tag: `pre-redesign-2026-11-16` (intact).
Nothing is committed, pushed, or deployed.

## Recommendation

**Conditional go.** The site builds cleanly, every route is full width with no overflow at 390 to 2560 px, and Lighthouse scores 100 for accessibility, best practices and SEO on all seven audited routes. Publishing the Projects pages is approved. Deploy after the two remaining approvals in "Deployment readiness": the commit, merge and push, and the patched lockfile.

## 1. Full-width implementation

The visual identity is unchanged: colours, typefaces, palette, component styling and icons are as approved. Only widths, gutters and column counts changed.

| Change | File |
| --- | --- |
| Removed the 1180 px page cap. `.container` is now `width: 100%` with gutter padding only. | `src/styles/global.css`, `src/styles/tokens.css` |
| Gutters: 48 px desktop, 24 px at 1024 px and below, 16 px at 640 px and below, through one `--gutter` token. | `src/styles/tokens.css` |
| Post lists flow into more columns instead of stretching rows: 1 column to about 1500 px, 2 at 1920, 3 at 2560. | `src/styles/ui.css` |
| Writeup entry lists use the same column rule. | `src/pages/writeups/index.astro` |
| Project cards use `auto-fill`, so two cards keep a sensible width on wide screens instead of stretching. | `src/pages/projects/index.astro` |
| Home: hero heading, mascot HUD, index card, lead card height and about card scale with the viewport. | `src/pages/index.astro` |
| Article: breadcrumb, contents menu, related grid and footer note run full width. The prose column is held to `--reading` (46rem) and centred in the space beside the contents menu. Related posts use `auto-fill` columns. | `src/layouts/WriteupLayout.astro` |

Header, footer, hero, stats, featured cards, category cards, About, Achievements, project detail and 404 inherit the change from `.container`.

Images keep their aspect ratio (`object-fit: cover` inside fixed-ratio frames, or `height: auto`).

## 2. Before and after

Pairs at 1920 and 2560 px, before on the left: `docs/redesign/pairs/<route>-<width>-before-after.webp` for home, blog, writeups, research, projects, about, reader and notfound (16 files).

- Before set, all five widths: `docs/redesign/before/`
- After set, all five widths: `docs/redesign/shots/`
- Reference comparison from the first pass: `docs/redesign/compare-home.webp`

At 2560 px the homepage previously used 1180 px (46% of the width). It now uses 2464 px.

## 3. Responsive results

Captured with `node scripts/shoot.mjs` at 390, 768, 1440, 1920 and 2560 px. Overflow is measured with the page's `overflow-x: hidden` lifted, so it cannot be masked.

| Route | 390 | 768 | 1440 | 1920 | 2560 | Overflow | Console errors |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Home | pass | pass | pass | pass | pass | 0 | 0 |
| Blog | pass | pass | pass | pass | pass | 0 | 0 |
| Writeups | pass | pass | pass | pass | pass | 0 | 0 |
| Research | pass | pass | pass | pass | pass | 0 | 0 |
| Projects, project detail | pass | pass | pass | pass | pass | 0 | 0 |
| About | pass | pass | pass | pass | pass | 0 | 0 |
| Achievements | pass | pass | pass | pass | pass | 0 | 0 |
| Article (two posts) | pass | pass | pass | pass | pass | 0 | 0 |
| 404 | pass | pass | pass | pass | pass | 0 | the expected 404 only |

Navigation: the six links show from 881 px up; the menu button opens and closes the panel at 375 and 768 px, and Escape closes it. Gutter token read back as 24 px at 768 and 48 px at 1920.

## 4. Security

### Independent reviews

- **Codex:** did not run. The CLI returned "Your access token could not be refreshed because your refresh token has expired". Fix with `codex logout` then `codex login`.
- **Claude Security:** did not run. Its change scan reads committed changes only, and this work is uncommitted by instruction. The whole-codebase scan was offered and declined at the cost confirmation.
- The site-code review below is therefore my own, not an independent one.

### Dependency advisories

`npm audit` reported 17 advisories (12 in production dependencies, 5 more in dev tooling). `npm audit fix` (no `--force`) was applied: 25 packages changed inside their existing semver ranges, `package.json` unchanged. Regression check: all 196 built HTML files are byte-identical before and after (asset hashes normalised), and `astro check` is clean. **3 remain**, all needing Astro 7.

Context for exploitability: the output is static HTML on GitHub Pages. There is no server runtime, no SSR adapter, no image endpoint, and `astro:assets` is not used. Dependencies run only at build time and in the local dev server, on author-controlled content.

| Package | Advisories | Affected | Severity | Exploitable here | Fixed in | Status |
| --- | --- | --- | --- | --- | --- | --- |
| astro | GHSA-26w7-cxv4-gfx2 (RCE via AVIF image optimisation) | < 7.2.8 | critical | No. Needs the image optimisation pipeline processing attacker-supplied AVIF. The site does not use it and has no AVIF files. | 7.2.8 | **Open: breaking upgrade** |
| astro | GHSA-f48w-9m4c-m7f5, GHSA-7pw4-f3q4-r2p2, GHSA-4g3v-8h47-v7g6, GHSA-98hj-9722-w3j8, GHSA-mh32-jxcr-mh9f (XSS in rendering) | up to 7.4.4 | low to moderate | No. They need untrusted input reaching templates at render time; all input is repository content. | 7.4.5 | **Open: breaking upgrade** |
| astro | GHSA-376h-93r7-7g6f, GHSA-r3h5-4585-7x3w (base path check, `@astrojs/node` image endpoint) | up to 7.4.6 | moderate | No. No `base`, no Node adapter. | 7.4.7 | **Open: breaking upgrade** |
| sharp | GHSA-f88m-g3jw-g9cj, GHSA-rgj7-g3m4-5g8c, GHSA-wq5f-xc86-pv6w (libvips, libheif, librsvg) | < 0.35.5 | high | No. sharp only runs in local helper scripts on your own images. | 0.35.5 | **Open: pinned by Astro 6** |
| esbuild | GHSA-g7r4-m6w7-qqqr (dev server file read on Windows) | 0.27.3 to 0.28.0 | low | Local dev only, and only if the dev server is reachable by others. Astro binds to localhost by default. | 0.28.1 | **Open: pinned by Astro 6** |
| vite | GHSA-587h-7wmj-h5pm, GHSA-r825-w8mm-5pxw, GHSA-698v-4r3x-3vcv, GHSA-9jrq-w75r-8gcw, GHSA-rq7h-c2jc-7f22 | 7.0.0 to 7.3.6 | high | Dev server only. | 7.3.7 | Fixed (7.3.8) |
| devalue | GHSA-j22f-vq7h-c4qm, GHSA-mcm9-63f2-9j32, GHSA-x5rw-q4pp-hg5g, GHSA-r9w8-h9r3-54w4 and 4 lower | up to 5.9.2 | high | No. No untrusted serialised input. | 5.9.3 | Fixed (5.9.4) |
| zod | GHSA-mrhx-c7xc-m3w5 | < 4.6.6 | high | No. Validates only frontmatter. | 4.6.6 | Fixed (4.6.7) |
| postcss | GHSA-r28c-9q8g-f849, GHSA-fxqj-rqcc-2cmp | up to 8.5.22 | high | No. Processes only repository CSS. | 8.5.23 | Fixed (8.5.33) |
| svgo | GHSA-2p49-hgcm-8545, GHSA-w27v-7q3p-w38r, GHSA-4vpr-x523-8j87 | 4.0.0 to 4.0.2 | high | No. No untrusted SVG is sanitised. | 4.1.0 | Fixed (4.1.0) |
| js-yaml | GHSA-52cp-r559-cp3m, GHSA-5p4m-2wfm-xmqj, GHSA-2883-xcg3-v3hh | 4.0.0 to 4.3.1 | high | No. Parses only frontmatter. | 4.3.2 | Fixed (4.3.2) |
| nanoid | GHSA-28wg-ghj8-5hjv, GHSA-2v37-7h3g-55p8 | up to 3.3.17 | high | No. | 3.3.18 | Fixed (3.3.20) |
| smol-toml | GHSA-7w5x-hrqm-74c2, GHSA-r4xh-jqrq-34v2 | up to 1.8.0 | high | No. | 1.8.1 | Fixed (1.9.1) |
| source-map-js | GHSA-68fv-2mgg-jv7q | 1.0.0 to 1.2.1 | high | No. | 1.2.2 | Fixed (1.2.2) |
| fast-uri (dev) | GHSA-v2hh-gcrm-f6hx and 10 others | 3.0.0 to 3.1.8 | high | No. Editor tooling only. | 3.1.9 | Fixed (3.1.9) |
| yaml and language-server chain (dev) | GHSA-48c2-rrv3-qjmp | 2.0.0 to 2.8.2 | moderate | No. Editor tooling only. | 2.8.3 | Fixed (2.9.0) |

Remediation for the three open items: upgrade Astro 6 to 7 as its own change, with a full rebuild and this report's regression sweep. It was not applied because it is a major version.

### Site code

- Raw HTML in Markdown passes through, but all content is author-controlled. Payload samples sit inside code blocks; the built pages contain no live event-handler attributes.
- `set:html` is used only for static icon strings.
- The URL search term is written to an input value and compared as text.
- No secrets matched in tracked files.
- All 190 external links that open a new tab carry `noopener`.
- The Spotify player on `/about/` now loads only when the visitor asks for it, so no third-party cookies are set on page load.
- GitHub Pages cannot send custom headers, so there is no Content-Security-Policy. `netlify.toml` headers apply only on Netlify.
- Google Fonts is still requested on every page.

## 5. Lighthouse

Lighthouse 13.6.0 against the production build (`astro preview`), driven through Edge. Script: `bash scripts/lighthouse.sh [mobile|desktop]`.

| Route | Mobile perf / a11y / BP / SEO | Mobile LCP, CLS, TBT | Desktop perf / a11y / BP / SEO | Desktop LCP |
| --- | --- | --- | --- | --- |
| Home | 98 / 100 / 100 / 100 | 2.3 s, 0, 0 ms | 90 / 100 / 100 / 100 | 2.0 s |
| Blog | 100 / 100 / 100 / 100 | 1.5 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.4 s |
| Writeups | 100 / 100 / 100 / 100 | 1.4 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.4 s |
| Research | 100 / 100 / 100 / 100 | 1.4 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.4 s |
| Projects | 100 / 100 / 100 / 100 | 1.4 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.4 s |
| About | 100 / 100 / 100 / 100 | 1.4 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.4 s |
| Article | 86 / 100 / 100 / 100 | 4.1 s, 0, 0 ms | 100 / 100 / 100 / 100 | 0.7 s |

Problems found by the first run and fixed, then confirmed by rerun:

| Problem | Before | Fix | After |
| --- | --- | --- | --- |
| Article layout shift | CLS 0.265 | Fallback fonts sized to match the web fonts; contents menu collapsed by CSS, not by script after load | 0 |
| Layout shift on listing pages | up to 0.052 | Same font fallback | 0 |
| Home stats markup (`definition-list`, `dlitem`) | a11y 92 | Stats are now a list | 100 |
| Blog heading order | a11y 98 | Added a visually hidden `h2` above the post rows | 100 |
| About third-party cookies | BP 77 | Spotify player loads on request | 100 |
| Contents links under 24 px tall | a11y 96 on article | Minimum height 24 px | 100 |

Still open:

- Article on mobile: LCP 4.1 s under simulated slow 4G. The largest element is the post's cover PNG (177 KB for this post). Covers are unoptimised originals in `public/`.
- Home LCP is the mascot. Observed paint is about 0.2 s; the 2.0 to 2.3 s figures are Lighthouse's simulated throttling. A 360 px variant is now served to small screens.
- Google Fonts CSS is render-blocking (estimated 0.7 s on slow mobile). Self-hosting the fonts would remove it.

Keyboard and motion: focus ring verified by tabbing (2 px `#A3FF12` outline); Ctrl+K focuses search; Escape closes the menu; `prefers-reduced-motion` rules are present and disable the mascot entrance, ring rotation, caret and page transitions. No screen reader pass was run.

## 6. Final regression

| Check | Result |
| --- | --- |
| `npm run build` | Pass. 196 pages, `astro check` 0 errors, 0 warnings, 0 hints. |
| Article URLs | Unchanged. `src/content/` has no diff against the tag; 187 writeup pages built (93 posts plus legacy redirect stubs). |
| Internal links | 2436 checked, 0 broken. |
| Local images | 562 references, 0 missing. |
| Every built page at 390 and 2560 px (`node scripts/check-pages.mjs`, 390 loads) | 0 overflow, 0 pages without an `h1`, 0 broken local images, 0 script errors. |
| Title, description, canonical | Present on every non-redirect page. |
| Search, filters, pagination | Pass: `?q=volatility` gives 1 of 93; all gives 12 rows, page 1 of 8; next gives `?page=2`; CTF filter gives 59, page 1 of 5; empty state and reset work. |
| Mobile navigation | Pass at 375 and 768 px. |
| Contents menu on mobile | Failed first (list stayed open: a later CSS rule overrode the collapse). Fixed and retested: closed by default, opens, closes after a link is chosen. |
| Syntax highlighting | Pass: 92 pages contain highlighted code; a sample post shows 33 blocks, 9 token colours, 33 copy buttons. |

Failures that are content, not regressions (present before this work, `src/content/` untouched):

- `/writeups/international-ctf/cybergame-sk/{intergalactic-keypad,lesser-less,shifted-payload}/`: the cover image is hotlinked from `https://cybergame.sk/img/CG26.sv.white.svg`, which now returns 404.
- 11 LigaCTF posts hotlink their cover from `pbs.twimg.com`. It loads (HTTP 200) but is blocked by browsers with tracking prevention.
- 118 article pages have more than one `h1`, because the Markdown bodies use `#` headings below the page title. The first report's "one h1 per page" holds for listing pages only.

## 7. Remaining limitations

- Astro 7 upgrade outstanding (3 advisories, none exploitable on the static site).
- No independent security review ran (Codex login expired; Claude Security declined).
- Cover images are unoptimised; three are broken remote links and eleven depend on Twitter's CDN.
- Fonts come from Google Fonts.
- No light theme, so no theme toggle. The constellation canvas component is unused.
- No Content-Security-Policy on GitHub Pages.
- Tested in Chromium (Edge) only. No screen reader pass.
- `docs/redesign/` holds 17 MB of screenshots. Decide whether to commit them.

## 8. Deployment readiness

Ready: build, links, images, responsive layout, accessibility scores, SEO tags, rollback tag.

Needs your approval before deploy:

1. **Projects pages. Approved 2026-11-16.** `/projects/`, `/projects/awd-watchdog/` and `/projects/wavesentinel-wids/` were hidden before the redesign and will be published with it, with a Projects link in the header, footer and homepage.
2. **Commit, merge and push.** Push to `master` triggers the GitHub Pages deploy.
3. **Dependency lockfile.** `package-lock.json` now carries the 25 patched packages. Approve including it.

Recommended soon after, not blocking: Astro 7 upgrade; re-host the 14 remote cover images locally; `codex login` and a Codex or Claude Security pass on the committed branch.

```powershell
npm run build
npx astro preview --port 4322
node scripts/check-pages.mjs
git add -A
git commit -m "feat: monochrome redesign, full-width layout"
git checkout master
git merge redesign/monochrome
git push origin master
```

Rollback before merge: `git checkout master`. After deploy: `git revert` the merge commit and push, or reset `master` to `pre-redesign-2026-11-16`.

**Go, conditional on approvals 2 and 3. Approval 1 (Projects) is given.**

---

## Appendix: first-pass summary

- Design system: `src/styles/tokens.css` (tokens), `src/styles/global.css` (base), `src/styles/ui.css` (shared components), `src/components/Icon.astro`, `src/components/PostRow.astro`.
- Mascot: `public/images/brand/mascot-original.png` is the supplied file. Derivatives are resizes only (`mascot.webp`, `mascot-360.webp`, `mascot-96.png`, `favicon.png`, `apple-touch-icon.png`).
- Routes added: `/blog/`, `/research/`, `/about/`, 404. `/writeups/` regrouped. `/achievements/` kept. Cheatsheets remain unpublished.
- Homepage differences from the reference are deliberate and come from the no-invented-data rule: real counts, three newest posts as featured, real sections as categories, GitHub as the only social link, no CellShield card.
- Reader: sticky contents menu, heading anchors, syntax highlighting wired up, copy buttons, keyboard-reachable scroll regions.
