# 0xG10D blog

Markdown-first cybersecurity writeup site for 0xG10D. The site covers CTF writeups, Hack The Box notes, TryHackMe notes, malware analysis writeups, security projects, and cybersecurity learning notes.

## Decisions

- Obsidian `[[wikilink]]` and `![[image.png]]` syntax is supported by a local remark plugin.
- Finished writeups are published by copying Markdown files into `src/content/writeups/`.
- Frontmatter uses strict lowercase enums so taxonomy mistakes fail the build.

## Local setup

```powershell
npm install
npm run dev
```

Open the local URL printed by Astro.

## Validate before publishing

```powershell
npm install
npm run build
npm run preview
```

## Future deployment

Do not deploy until the site content is ready. When it is ready, use the `0xG10D.github.io` identity and connect the GitHub repo to Netlify.

Netlify settings:

   - Build command: `npm run build`
   - Publish directory: `dist`
   - Production branch: `main`

Netlify also reads `netlify.toml`, so future pushes to `main` can rebuild the live site automatically once deployment is enabled.

## Content workflow

Read `docs/publishing-workflow.md` before adding real writeups.
