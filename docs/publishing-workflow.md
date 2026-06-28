# Publishing Workflow

This site is Markdown-first. Write in Obsidian, then copy finished notes into the
Astro content folder when they are ready for 0xG10D blog.

## Decisions

### Obsidian syntax

Keep native Obsidian syntax. The local remark plugin at
`src/plugins/remark-obsidian-links.mjs` converts wikilinks during the Astro build.

Supported patterns:

- `[[Sample HTB Cicada Notes]]` becomes `/writeups/sample-htb-cicada-notes/`.
- `[[sample-htb-cicada-notes|custom label]]` becomes a normal link with `custom label`.
- `![[scan-overview.svg]]` becomes an image from the current writeup image folder.

### Vault-to-site sync

Use manual copy. Do not symlink the Obsidian vault into the repo.

Reason: manual copy is more reliable on Windows and in CI. Netlify only builds files
that exist in the repository checkout, so an external vault path will break deployment.

## Publish a new writeup

1. Finish the note in Obsidian.
2. Rename the file to lowercase kebab-case, such as `forest-ad-enumeration.md`.
3. Add frontmatter at the top of the file.
4. Copy the file into `src/content/writeups/`.
5. Copy images into `public/images/writeups/<writeup-slug>/`.
6. Run `npm run build`.
7. Review the page locally before pushing.

The writeup slug comes from the Markdown filename. For example:

```text
src/content/writeups/forest-ad-enumeration.md
```

renders at:

```text
/writeups/forest-ad-enumeration/
```

## Frontmatter

Every writeup needs valid frontmatter. The build fails if taxonomy values are mistyped.
Use lowercase kebab-case values.

```yaml
---
title: "Forest AD Enumeration"
summary: "Short card summary for the writeups page."
date: 2026-06-18
tags: ["nmap", "smb", "kerberos"]
category: "active-directory"
difficulty: "easy"
platform: "hack-the-box"
boxImage: ""
draft: false
---
```

Fields:

- `title`: page title and card title.
- `summary`: short description shown on cards and used as metadata.
- `date`: publish date in `YYYY-MM-DD` format.
- `tags`: lowercase kebab-case tags used by filters.
- `category`: main topic area.
- `difficulty`: lab or note difficulty.
- `platform`: source platform.
- `boxImage`: optional machine/box logo URL or local image path.
- `draft`: controls whether the writeup is public.

Valid categories:

- `active-directory`
- `web-exploitation`
- `binary-exploitation`
- `forensics`
- `cryptography`
- `cloud`
- `mobile`
- `network`
- `research`
- `tryhackme`
- `international-ctf`
- `local-ctf`
- `misc`

Valid difficulties:

- `easy`
- `medium`
- `hard`
- `insane`
- `info`

Valid platforms:

- `hackthebox`
- `hack-the-box`
- `tryhackme`
- `portswigger`
- `picoctf`
- `research`
- `ctf`
- `other`

## Images

For a writeup named:

```text
src/content/writeups/forest-ad-enumeration.md
```

put images here:

```text
public/images/writeups/forest-ad-enumeration/
```

Then embed them in Obsidian syntax:

```md
![[bloodhound-path.png]]
```

During the build, that becomes:

```text
/images/writeups/forest-ad-enumeration/bloodhound-path.png
```

Use clear image names such as `nmap-results.png`, `web-login.png`, or
`bloodhound-path.png`. Avoid screenshots that expose private tokens, client data,
VPN configs, or active-machine spoilers.

## HTB Box Images

Use `boxImage` when you want a Hack The Box machine logo or CTF event logo to
appear on the writeup card and individual writeup page.

External HTB image URL:

```yaml
boxImage: "https://example.com/htb-machine-image.png"
```

Local image:

```yaml
boxImage: "/images/writeups/forest-ad-enumeration/box.png"
```

For local images, put the file here:

```text
public/images/writeups/forest-ad-enumeration/box.png
```

Leave the value empty while you are still collecting images:

```yaml
boxImage: ""
```

## Import International and Local CTF Writeups

International CTF and Local CTF notes are imported as cleaned copies. Do not
symlink the vault and do not edit the source vault files during import.

Use event-based folders under the content collection:

```text
src/content/writeups/international-ctf/<event-name>/<challenge-name>.md
src/content/writeups/local-ctf/<event-name>/<challenge-name>.md
```

These routes render through the catch-all writeup route:

```text
/writeups/international-ctf/<event-name>/<challenge-name>/
/writeups/local-ctf/<event-name>/<challenge-name>/
```

Current CTF event folders:

- `international-ctf/cybergame-sk/`
- `international-ctf/umassctf2026/`
- `local-ctf/iboh25/`
- `local-ctf/international-hack10-ctf-2026/`
- `local-ctf/ligactf2026/`
- `local-ctf/umcs-preliminary/`

International CTF frontmatter uses:

```yaml
category: "international-ctf"
platform: "ctf"
draft: false
boxImage: "https://event-logo.example/logo.png"
```

Local CTF frontmatter uses:

```yaml
category: "local-ctf"
platform: "ctf"
draft: false
boxImage: "https://event-logo.example/logo.png"
```

Use an event tag when useful, for example:

- `cybergame-sk`
- `umassctf2026`
- `iboh25`
- `hack10`
- `ligactf2026`
- `umcs-preliminary`

Flag policy:

- HTB flags must stay redacted as `[REDACTED_FLAG]`.
- International CTF and Local CTF challenge flags may remain visible.
- Do not guess or fabricate missing flags; restore them only from the original
  source note or challenge material.
- Still redact non-flag secrets everywhere: real passwords, API keys, bot tokens,
  private keys, personal email, local personal paths, identity details, and
  unnecessary VPN/local attacker IPs.

The Local CTF import intentionally ignores these folders:

- `HYNX CTF`
- `HNYX CTF` when that spelling appears in the vault
- `UMCS Final AWD`

Do not import notes, screenshots, or attachments from those folders.

For images, copy only referenced and safe screenshots into:

```text
public/images/writeups/<category>/<event-name>/<challenge-name>/
```

Then reference them with public paths:

```md
![alt text](/images/writeups/<category>/<event-name>/<challenge-name>/image-name.png)
```

Use event logo URLs through `boxImage`. External image URLs can expire or block
hotlinking. A later hardening pass can save stable event logos locally under:

```text
public/images/events/
```

and then point `boxImage` at `/images/events/<event>.png`.

Before publishing or deploying imported CTF posts, run the build and privacy scan:

```powershell
npm run build
rg -n "HTB\{[^}\r\n]+\}" src\content\writeups\htb-*.md
rg -n -i "<personal-name>|<personal-handle>|LinkedIn|student\\.example|@student|C:\\Users\\<username>|PRIVATE KEY|BEGIN RSA|BEGIN OPENSSH|BEGIN EC|BEGIN DSA|SENSOR_API_KEY=rw_sk_|api_key\s*=|token\s*=|password\s*=" src public dist
```

Review every match. CTF flags under `international-ctf/` and `local-ctf/` are
allowed. Redact HTB flags, real credentials, local personal paths, identity
details, private keys, tokens, and unsafe screenshots before publishing.

## Import TryHackMe Writeups

TryHackMe notes are imported as cleaned copies from the Obsidian vault. Do not
symlink the vault and do not edit, move, or delete source vault files during
import.

Use this content folder:

```text
src/content/writeups/tryhackme/
```

If each room has one writeup, keep the file flat and readable:

```text
src/content/writeups/tryhackme/cheese-ctf.md
```

That renders through the catch-all writeup route:

```text
/writeups/tryhackme/cheese-ctf/
```

If a room later needs multiple notes, use a room folder:

```text
src/content/writeups/tryhackme/<room-name>/<writeup-name>.md
```

TryHackMe frontmatter should use:

```yaml
category: "tryhackme"
platform: "tryhackme"
draft: false
boxImage: ""
```

Use lowercase kebab-case tags such as:

- `tryhackme`
- `linux`
- `web`
- `lfi`
- `privilege-escalation`

TryHackMe flag policy:

- TryHackMe room flags and answers may remain visible in local writeups.
- Do not redact normal TryHackMe flags unless they expose personal secrets.
- Still redact real passwords, API keys, private keys, personal email, local
  Windows paths, real tokens, real identity details, and unsafe screenshots.

For images, convert Obsidian embeds like:

```md
![[Pasted image 20260617232341.png]]
```

to public image paths:

```md
![Cheese CTF completion screen](/images/writeups/tryhackme/cheese-ctf/pasted-image-20260617232341.png)
```

Copy safe referenced images into:

```text
public/images/writeups/tryhackme/<room-slug>/
```

Leave `boxImage: ""` unless a safe, real TryHackMe room icon exists. To add a
room icon later, copy it into the room image folder and set:

```yaml
boxImage: "/images/writeups/tryhackme/<room-slug>/box.png"
```

Before public deployment, review every imported TryHackMe writeup for reusable
credentials, local paths, profile screenshots, private dashboards, and accidental
identity details even when `draft: false` is already set.

## Internal Links

Use Obsidian wikilinks between writeups:

```md
See [[windows-privesc-checklist]] for the checklist.
```

With custom link text:

```md
See [[windows-privesc-checklist|the Windows privesc checklist]].
```

The target writeup should use a matching lowercase kebab-case filename:

```text
src/content/writeups/windows-privesc-checklist.md
```

## Draft Mode

Use `draft: true` while cleaning a writeup.

Draft writeups:

- pass schema validation if their frontmatter is valid
- do not appear on the home page
- do not appear on `/writeups/`
- do not get generated as public writeup routes

Publish by changing:

```yaml
draft: true
```

to:

```yaml
draft: false
```

`draft: false` means the writeup is visible in local production builds and any
future static deployment output. Treat that flip as a publish review gate, not
just a UI toggle.

Before real deployment, review every `draft: false` HTB post for active-machine
policy, flags, hashes, tokens, private keys, reusable credentials, personal paths,
and screenshots that expose profile or VPN details.

## Site Logo

To add a site logo, place the file here:

```text
public/images/logo.png
```

The header automatically shows `/images/logo.png` beside `0xG10D blog` when the
file exists. If the file is missing, the terminal-style fallback mark remains.

## Test Before Pushing

Run these commands from the repo root:

```powershell
cd <repo-root>
npm install
npm run dev
```

Open the local URL printed by Astro. Usually:

```text
http://localhost:4321
```

Before pushing, run:

```powershell
npm run build
npm run preview
```

Fix every build error before pushing. A clean build means Astro checked the content
schema, Markdown rendering, routes, and static output.
