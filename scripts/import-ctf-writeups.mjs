import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const intlRoot = process.env.INTL_CTF_ROOT;
const localRoot = process.env.LOCAL_CTF_ROOT;

if (!intlRoot || !localRoot) {
  throw new Error('Set INTL_CTF_ROOT and LOCAL_CTF_ROOT before running this script.');
}

const writeupRoot = path.join(repoRoot, 'src', 'content', 'writeups');
const imageRoot = path.join(repoRoot, 'public', 'images', 'writeups');
const privateRedactionTerms = (process.env.PRIVATE_REDACTION_TERMS ?? '')
  .split(',')
  .map((term) => term.trim())
  .filter(Boolean);
const localExclusions = new Set(['HYNX CTF', 'HNYX CTF', 'UMCS Final AWD']);
const knownEvents = new Map([
  ['CyberGame.SK', { label: 'CyberGame.SK', slug: 'cybergame-sk' }],
  ['UMassCTF2026', { label: 'UMassCTF 2026', slug: 'umassctf2026' }],
  ['IBOH25', { label: 'IBOH25', slug: 'iboh25' }],
  ['International HACK@10 CTF 2026', { label: 'International HACK@10 CTF 2026', slug: 'international-hack10-ctf-2026' }],
  ['LigaCTF2026', { label: 'LigaCTF 2026', slug: 'ligactf2026' }],
  ['UMCS Prelimanry', { label: 'UMCS Preliminary', slug: 'umcs-preliminary' }]
]);

const eventLogos = new Map([
  [
    'cybergame-sk',
    'https://media.licdn.com/dms/image/v2/D4D0BAQFd86qlfTQQ6Q/company-logo_200_200/B4DZxyNgX5GUAI-/0/1771442669430/cybergame_sk_logo?e=1783555200&v=beta&t=nZxCj9-72lUIAVI04ESSVk6REWcSnYQ8BG6DQRH77i0'
  ],
  [
    'iboh25',
    'https://www.crest-approved.org/wp-content/uploads/2025/11/International-Battle-of-Hackers-IBOH-2025.png'
  ],
  [
    'international-hack10-ctf-2026',
    'https://instagram.fkul11-2.fna.fbcdn.net/v/t51.82787-19/641307447_17850468132650020_693182401274637569_n.jpg?stp=dst-jpg_s150x150_tt6&efg=eyJ2ZW5jb2RlX3RhZyI6InByb2ZpbGVfcGljLmRqYW5nby4xMDgwLmMyIn0&_nc_ht=instagram.fkul11-2.fna.fbcdn.net&_nc_cat=104&_nc_oc=Q6cZ2gGY8elv-2_ffeNAnV1zev1x6qjeFXKSTkqJPt8hLvpW4r7SjGcF8yWitQhjEUVMFOlCO1QdwosRBu2_nqdaMwi1&_nc_ohc=V5UmcoEFIBIQ7kNvwH4oZxS&_nc_gid=nKZjHtkfrQHa4bxkteBcUA&edm=APoiHPcBAAAA&ccb=7-5&oh=00_Af_eyJvKyalWBh43tjTkFFQWtcGJPfalqqEqSEqMK-rTpQ&oe=6A3A2E75&_nc_sid=22de04'
  ],
  [
    'ligactf2026',
    'https://media.licdn.com/dms/image/v2/D560BAQEUbVka6Dh0pw/company-logo_200_200/company-logo_200_200/0/1719257546509/owaspmalaysia_logo?e=1783555200&v=beta&t=t-CxbA7McXV5OLHwPAAnkp0Ljv3IKDVBYtUUhhCzmUw'
  ],
  [
    'umcs-preliminary',
    'https://umcybersec.site/assets/logo-BsYk-M08.png'
  ]
]);

const eventTags = new Map([
  ['cybergame-sk', 'cybergame-sk'],
  ['umassctf2026', 'umassctf2026'],
  ['iboh25', 'iboh25'],
  ['international-hack10-ctf-2026', 'hack10'],
  ['ligactf2026', 'ligactf2026'],
  ['umcs-preliminary', 'umcs-preliminary']
]);

const forcedDifficulties = new Map([
  ['easy', 'easy'],
  ['medium', 'medium'],
  ['hard', 'hard'],
  ['insane', 'insane']
]);

function walk(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(fullPath);
    return entry.isFile() ? [fullPath] : [];
  });
}

function slugify(value) {
  return value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function titleCase(value) {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b([a-z])/g, (match) => match.toUpperCase())
    .replace(/\bCtf\b/g, 'CTF')
    .replace(/\bRe\b/g, 'RE')
    .replace(/\bSsrF\b/g, 'SSRF');
}

function yamlEscape(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function stripSourceFrontmatter(raw) {
  let text = raw.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').trimStart();

  const fenceMatch = text.match(/^````?markdown\s*\n([\s\S]*?)\n````?\s*$/i);
  if (fenceMatch) text = fenceMatch[1].trimStart();

  if (text.startsWith('---\n')) {
    const end = text.indexOf('\n---', 4);
    if (end !== -1) text = text.slice(end + 4).trimStart();
  }

  const earlyFence = text.split('\n', 16).findIndex((line) => line.trim() === '---');
  if (earlyFence > 0) {
    const prelude = text.split('\n', earlyFence).join('\n');
    if (/^(title|toc|date|categories|tags|render_with_liquid):/im.test(prelude)) {
      text = text.split('\n').slice(earlyFence + 1).join('\n').trimStart();
    }
  }

  return text;
}

function extractMeta(text, fileBase, relParts) {
  const eventDir = relParts[0];
  const eventInfo = knownEvents.get(eventDir) ?? { label: titleCase(eventDir), slug: slugify(eventDir) };
  const categoryPrefixMatch = fileBase.match(/^([A-Za-z0-9 _/+-]+?)\s+-\s+(.+)$/);
  const filenameCategory = categoryPrefixMatch ? categoryPrefixMatch[1].trim() : '';
  const filenameChallenge = categoryPrefixMatch ? categoryPrefixMatch[2].trim() : fileBase.trim();

  const challengeLine =
    text.match(/^\s*(?:[-*]\s*)?(?:\*\*)?Challenge(?: Name)?(?:\*\*)?\s*[:|]\s*(?:\*\*)?([^*\n|]+?)(?:\*\*)?\s*$/im) ??
    text.match(/^\|\s*Challenge\s*\|\s*([^|\n]+)\|/im);
  const rawTitle = challengeLine?.[1]?.trim() || filenameChallenge;
  const title = titleCase(
    rawTitle
      .replace(/\s+-\s+Malware Analysis$/i, '')
      .replace(/\s*\(.*?write-?up.*?\)\s*$/i, '')
      .replace(/\s+Write-?up$/i, '')
  );

  const categoryLine =
    text.match(/^\s*(?:[-*]\s*)?(?:\*\*)?Category(?:\*\*)?\s*[:|]\s*(?:\*\*)?([^*\n|]+?)(?:\*\*)?\s*$/im) ??
    text.match(/^\|\s*Category\s*\|\s*([^|\n]+)\|/im);
  const categoryText = [filenameCategory, categoryLine?.[1] ?? '', fileBase, text.slice(0, 1800)].join(' ').toLowerCase();
  const difficultyText = text.match(/difficulty\s*[:|]\s*(?:\*\*)?([^*\n|]+?)(?:\*\*)?\s*$/im)?.[1]?.toLowerCase() ?? '';

  const tags = new Set(['ctf']);
  const eventTag = eventTags.get(eventInfo.slug);
  if (eventTag) tags.add(eventTag);
  if (/web|ssrf|php|flask|crm|upload|idor/.test(categoryText)) tags.add('web');
  if (/forensics?|pcap|network|steg|image|png|wireshark|memory|log/.test(categoryText)) tags.add('forensics');
  if (/reverse|reversing|binary analysis|malware|apk|android|elf|pe\b/.test(categoryText)) tags.add('reverse-engineering');
  if (/malware|c2|apk|detonat|loader|telegram/.test(categoryText)) tags.add('malware-analysis');
  if (/crypto|rsa|xor|rot13|braille|zipcrypto/.test(categoryText)) tags.add('cryptography');
  if (/pwn|binary exploitation|uaf|ret2win|rop/.test(categoryText)) tags.add('binary-exploitation');
  if (/boot2root|privilege escalation|linux|ssh|grafana|ftp/.test(categoryText)) tags.add('boot2root');
  if (/mobile|android|apk/.test(categoryText)) tags.add('mobile');
  if (/network|pcap|wireshark|c2 server/.test(categoryText)) tags.add('network');
  if (tags.size === 1) tags.add('misc');

  const difficulty = forcedDifficulties.get(difficultyText.match(/easy|medium|hard|insane/)?.[0] ?? '') ?? 'medium';
  const focus = [...tags].filter((tag) => tag !== 'ctf').slice(0, 3).join(', ').replace(/-/g, ' ');
  const summary = `${eventInfo.label} ${focus || 'CTF'} writeup covering ${title} with analysis, solution steps, and final recovery notes.`;

  return { eventInfo, title, tags: [...tags], difficulty, summary };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function redactPrivateTerms(text) {
  if (privateRedactionTerms.length === 0) return text;
  const pattern = new RegExp(privateRedactionTerms.map(escapeRegExp).join('|'), 'gi');
  return text.replace(pattern, '[REDACTED_IDENTITY]');
}

function redact(text) {
  return redactPrivateTerms(text)
    .replace(/[\w.+-]+@student[\w.-]*/gi, '[REDACTED_EMAIL]')
    .replace(/C:\\Users\\[^\\\s`)"']+\\[^\s`)"']*/gi, '[REDACTED_LOCAL_PATH]')
    .replace(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g, '[REDACTED_LOCAL_IP]')
    .replace(/\broot\.txt\b/gi, '[REDACTED_ROOT_FILE]')
    .replace(/\buser\.txt\b/gi, '[REDACTED_USER_FILE]')
    .replace(/(bot)?\d{8,12}:AA[A-Za-z0-9_-]{20,}/g, '$1[REDACTED_TOKEN]')
    .replace(/(\[FERNET_KEY\]\s*)[A-Za-z0-9_-]{20,}=*/g, '$1[REDACTED_TOKEN]')
    .replace(/\b(auth_token|SESSION_TOKEN|AUTH_TOKEN)=([A-Za-z0-9+/=_-]{12,})/g, '$1=[REDACTED_TOKEN]')
    .replace(/(Archive Password\s*:\s*)`?[^`\n]+`?/gi, '$1[REDACTED_PASSWORD]')
    .replace(/(^\s*password\s*:\s*)`?[^`\s]+`?/gim, '$1[REDACTED_PASSWORD]')
    .replace(/(^\s*(?:PASSWORD|PASSWD)\s*=\s*)`?[^`\s]+`?/gm, '$1[REDACTED_PASSWORD]')
    .replace(/(--password\s+)(?!\[REDACTED_)[^\s\\]+/gi, '$1[REDACTED_PASSWORD]')
    .replace(/(\bpassword:\s*)(?!str\b|bytes\b|Path\b|list\b|dict\b|float\b|int\b|!\[\[|\[REDACTED_)[^\s`]+/gi, '$1[REDACTED_PASSWORD]')
    .replace(/(^\s*(?:SESSION_TOKEN|auth_token|API_KEY|api_key|FERNET_KEY)\s*=\s*)(?!\[REDACTED_)[^\s`]+/gim, '$1[REDACTED_TOKEN]')
    .replace(/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
}

function repairEncoding(text) {
  return text
    .replace(/â€œ/g, '"')
    .replace(/â€\u009d/g, '"')
    .replace(/â€�/g, '"')
    .replace(/â€˜/g, "'")
    .replace(/â€™/g, "'")
    .replace(/â€\u0099/g, "'")
    .replace(/â€”/g, '-')
    .replace(/â€“/g, '-')
    .replace(/â€¦/g, '...')
    .replace(/Â /g, ' ')
    .replace(/Â/g, '');
}

function cleanMarkdown(text, title) {
  let cleaned = repairEncoding(stripSourceFrontmatter(text));
  cleaned = cleaned.replace(/^\s*#\s+.*?write-?up\s*\n+/i, '');
  cleaned = cleaned.replace(/^\s*#\s+Challenge Overview\s*\n+\s*#\s+Challenge Overview\s*/i, '# Challenge Overview\n');
  cleaned = cleaned.replace(new RegExp(`^\\s*#\\s+${title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\n+`, 'i'), '');
  cleaned = cleaned.replace(/\n{4,}/g, '\n\n\n').trim();
  return redact(cleaned);
}

function referencedImages(text) {
  const refs = [];
  const obsidian = /!\[\[([^\]\n|]+)(?:\|[^\]\n]+)?\]\]/g;
  const markdown = /!\[[^\]\n]*\]\((?!https?:\/\/|\/)([^)\n]+)\)/g;
  for (const match of text.matchAll(obsidian)) refs.push(match[1].trim());
  for (const match of text.matchAll(markdown)) refs.push(match[1].trim());
  return [...new Set(refs)];
}

function buildImageIndex(root) {
  const images = new Map();
  const valid = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg']);
  for (const file of walk(root)) {
    if (!valid.has(path.extname(file).toLowerCase())) continue;
    const key = path.basename(file).toLowerCase();
    if (!images.has(key)) images.set(key, []);
    images.get(key).push(file);
  }
  return images;
}

function imageTargetName(name, used) {
  const parsed = path.parse(name);
  const base = slugify(parsed.name) || 'image';
  const ext = parsed.ext.toLowerCase() || '.png';
  let candidate = `${base}${ext}`;
  let counter = 2;
  while (used.has(candidate)) {
    candidate = `${base}-${counter}${ext}`;
    counter += 1;
  }
  used.add(candidate);
  return candidate;
}

function nearestImage(candidates, sourceFile) {
  if (!candidates?.length) return undefined;
  const sourceDir = path.dirname(sourceFile).toLowerCase();
  return candidates
    .map((candidate) => {
      const dir = path.dirname(candidate).toLowerCase();
      const score = dir.startsWith(sourceDir) ? 0 : dir.includes(path.basename(sourceDir)) ? 1 : 2;
      return { candidate, score };
    })
    .sort((a, b) => a.score - b.score)[0].candidate;
}

function convertAndCopyImages(text, sourceFile, slugPath, imageIndex, copied) {
  const refs = referencedImages(text);
  if (refs.length === 0) return text;

  const slug = slugPath.replace(/\\/g, '/');
  const destDir = path.join(imageRoot, ...slug.split('/'));
  mkdirSync(destDir, { recursive: true });
  const usedNames = new Set();
  let updated = text;

  for (const ref of refs) {
    const decodedRef = decodeURIComponent(ref.replace(/^<|>$/g, ''));
    const direct = path.isAbsolute(decodedRef) ? decodedRef : path.resolve(path.dirname(sourceFile), decodedRef);
    const candidates = existsSync(direct) ? [direct] : imageIndex.get(path.basename(decodedRef).toLowerCase()) ?? [];
    const sourceImage = nearestImage(candidates, sourceFile);

    if (!sourceImage || !statSync(sourceImage).isFile()) {
      copied.missing.push({ source: sourceFile, image: ref });
      continue;
    }

    const targetName = imageTargetName(path.basename(sourceImage), usedNames);
    const target = path.join(destDir, targetName);
    copyFileSync(sourceImage, target);
    copied.images.push({ from: sourceImage, to: target });

    const publicPath = `/images/writeups/${slug}/${targetName}`;
    updated = updated.replaceAll(`![[${ref}]]`, `![${path.parse(targetName).name}](${publicPath})`);
    updated = updated.replace(new RegExp(`!\\[\\[${ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\|[^\\]\\n]+\\]\\]`, 'g'), `![${path.parse(targetName).name}](${publicPath})`);
    updated = updated.replaceAll(`](${ref})`, `](${publicPath})`);
  }

  return updated;
}

function collectSources() {
  const intl = walk(intlRoot)
    .filter((file) => file.toLowerCase().endsWith('.md'))
    .map((file) => ({ root: intlRoot, file, source: 'International CTF', category: 'international-ctf' }));

  const local = walk(localRoot)
    .filter((file) => file.toLowerCase().endsWith('.md'))
    .map((file) => ({ root: localRoot, file, source: 'Local CTF', category: 'local-ctf' }));

  return [...intl, ...local];
}

function sourcePreference(item) {
  if (statSync(item.file).size === 0) return 0;
  if (item.category === 'local-ctf') {
    const rel = path.relative(item.root, item.file);
    const firstPart = rel.split(path.sep)[0];
    if (localExclusions.has(firstPart)) return 0;
  }

  const raw = readFileSync(item.file, 'utf8');
  const relParts = path.relative(item.root, item.file).split(path.sep);
  const fileBase = path.basename(item.file, path.extname(item.file));
  const meta = extractMeta(raw, fileBase, relParts);
  return slugify(fileBase).includes(slugify(meta.title)) ? 1 : 0;
}

function shouldSkip(item) {
  const rel = path.relative(item.root, item.file);
  const parts = rel.split(path.sep);
  if (item.category === 'local-ctf' && localExclusions.has(parts[0])) {
    return `ignored excluded Local CTF folder: ${parts[0]}`;
  }
  if (statSync(item.file).size === 0) {
    return 'empty Markdown file';
  }
  return '';
}

function main() {
  const sources = collectSources().sort((a, b) => {
    const byPreference = sourcePreference(b) - sourcePreference(a);
    return byPreference || a.file.localeCompare(b.file);
  });
  const imageIndex = new Map([...buildImageIndex(intlRoot), ...buildImageIndex(localRoot)]);
  const hashes = new Map();
  const seenSlugs = new Set();
  const copied = { images: [], missing: [] };
  const report = {
    found: { international: [], local: [] },
    imported: [],
    skipped: [],
    images: copied.images,
    missingImages: copied.missing
  };

  for (const item of sources) {
    const rel = path.relative(item.root, item.file);
    if (item.category === 'international-ctf') report.found.international.push(rel);
    else report.found.local.push(rel);

    const skipReason = shouldSkip(item);
    if (skipReason) {
      report.skipped.push({ source: item.source, relative: rel, reason: skipReason });
      continue;
    }

    const raw = readFileSync(item.file, 'utf8');
    const hash = createHash('sha256').update(stripSourceFrontmatter(raw).trim()).digest('hex');
    if (hashes.has(hash)) {
      report.skipped.push({ source: item.source, relative: rel, reason: `duplicate content of ${hashes.get(hash)}` });
      continue;
    }
    hashes.set(hash, rel);

    const relParts = rel.split(path.sep);
    const fileBase = path.basename(item.file, path.extname(item.file));
    const meta = extractMeta(raw, fileBase, relParts);
    const challengeSlug = slugify(fileBase.replace(/\s+-\s+Malware Analysis$/i, ''));
    const eventSlug = meta.eventInfo.slug;
    let fileSlug = challengeSlug;
    let slugPath = `${item.category}/${eventSlug}/${fileSlug}`;
    let counter = 2;
    while (seenSlugs.has(slugPath)) {
      fileSlug = `${eventSlug}-${challengeSlug}-${counter}`;
      slugPath = `${item.category}/${eventSlug}/${fileSlug}`;
      counter += 1;
    }
    seenSlugs.add(slugPath);

    let content = cleanMarkdown(raw, meta.title);
    content = convertAndCopyImages(content, item.file, slugPath, imageIndex, copied);

    const frontmatter = [
      '---',
      `title: "${yamlEscape(meta.title)}"`,
      `summary: "${yamlEscape(meta.summary)}"`,
      `date: ${statSync(item.file).mtime.toISOString().slice(0, 10)}`,
      'tags:',
      ...meta.tags.map((tag) => `  - ${tag}`),
      `category: "${item.category}"`,
      `difficulty: "${meta.difficulty}"`,
      'platform: "ctf"',
      'draft: false',
      `boxImage: "${eventLogos.get(eventSlug) ?? ''}"`,
      '---',
      ''
    ].join('\n');

    const target = path.join(writeupRoot, `${slugPath}.md`);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, `${frontmatter}${content}\n`, 'utf8');
    report.imported.push({ source: item.source, relative: rel, target: path.relative(repoRoot, target), route: `/writeups/${slugPath}/` });
  }

  writeFileSync(path.join(repoRoot, '.backups', 'ctf-import-20260619', 'import-report.json'), JSON.stringify(report, null, 2), 'utf8');
  console.log(JSON.stringify(report, null, 2));
}

main();
