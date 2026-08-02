import type { CollectionEntry } from 'astro:content';

type WriteupEntry = CollectionEntry<'writeups'>;

const eventLabels: Record<string, string> = {
  'cybergame-sk': 'CyberGame.sk',
  'dfir-labs': 'DFIR Labs',
  'dicectf-2026': 'DiceCTF 2026',
  'hack-the-box-machines': 'Hack The Box Machines',
  'hack-the-box-sherlocks': 'Hack The Box Sherlocks',
  'iboh-2025': 'IBOH 2025',
  'international-hack10-ctf-2026': 'International Hack10 CTF 2026',
  'knightctf-2026': 'KnightCTF 2026',
  'letsdefend-jetbrains': 'LetsDefend JetBrains',
  'ligactf-2026': 'LigaCTF 2026',
  tryhackme: 'TryHackMe',
  'umassctf-2026': 'UMassCTF 2026',
  'umcs-preliminary': 'UMCS Preliminary'
};

const categoryLabels: Record<string, string> = {
  'active-directory': 'Active Directory',
  'binary-exploitation': 'Binary',
  cloud: 'Cloud',
  cryptography: 'Cryptography',
  forensics: 'Forensics',
  'hack-the-box': 'Machine',
  'international-ctf': 'CTF',
  'local-ctf': 'CTF',
  misc: 'Misc',
  mobile: 'Mobile',
  network: 'Network',
  research: 'Research',
  tryhackme: 'Room',
  'web-exploitation': 'Web'
};

const difficultyLabels: Record<string, string> = {
  easy: 'Easy',
  medium: 'Medium',
  hard: 'Hard',
  insane: 'Insane',
  info: 'Info'
};

export function getWriteupSlug(post: WriteupEntry) {
  return post.data.slug ?? post.id;
}

export function getWriteupUrl(post: WriteupEntry) {
  return `/writeups/${getWriteupSlug(post)}/`;
}

export function getEventSlug(post: WriteupEntry) {
  if (post.data.event) return post.data.event;
  return post.id.split('/')[0] ?? 'other';
}

export function getEventName(eventSlug: string) {
  return eventLabels[eventSlug] ?? eventSlug.split('-').map((part) => part[0]?.toUpperCase() + part.slice(1)).join(' ');
}

export function formatArchiveDate(date: Date) {
  return date.toLocaleDateString('en', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

export function formatDifficulty(value: string) {
  return difficultyLabels[value] ?? value;
}

export function getChallengeType(post: WriteupEntry) {
  const eventSlug = getEventSlug(post);
  const category = categoryLabels[post.data.category] ?? post.data.category.replaceAll('-', ' ');

  if (eventSlug === 'hack-the-box-machines') {
    return category === 'Machine' ? 'Machine' : `Machine / ${category}`;
  }

  if (eventSlug === 'hack-the-box-sherlocks') {
    return category === 'Forensics' ? 'Sherlock / Forensics' : `Sherlock / ${category}`;
  }

  if (eventSlug === 'dfir-labs') {
    return 'DFIR';
  }

  return category;
}

export function sortWriteupsNewestFirst(a: WriteupEntry, b: WriteupEntry) {
  return b.data.date.valueOf() - a.data.date.valueOf();
}

export function sortEventsByName(a: { name: string }, b: { name: string }) {
  return a.name.localeCompare(b.name);
}
