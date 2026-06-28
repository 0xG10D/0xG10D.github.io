export const securityIconNames = [
  'terminal',
  'target',
  'archive',
  'radar',
  'flask',
  'tool',
  'search',
  'file',
  'award',
  'platform',
  'github',
  'profile',
  'network',
  'shield',
  'code',
  'automation',
  'external'
] as const;

export type SecurityIconName = (typeof securityIconNames)[number];
