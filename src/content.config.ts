import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const tagSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'Use lowercase kebab-case tags, for example: active-directory');

const writeups = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/writeups' }),
  schema: z.object({
    title: z.string().min(1),
    summary: z.string().max(220).optional(),
    date: z.coerce.date(),
    tags: z.array(tagSchema).default([]),
    category: z.enum([
      'hack-the-box',
      'active-directory',
      'web-exploitation',
      'binary-exploitation',
      'forensics',
      'cryptography',
      'cloud',
      'mobile',
      'network',
      'research',
      'tryhackme',
      'international-ctf',
      'local-ctf',
      'misc'
    ]),
    difficulty: z.enum(['easy', 'medium', 'hard', 'insane', 'info']),
    platform: z.enum(['hackthebox', 'hack-the-box', 'tryhackme', 'portswigger', 'picoctf', 'research', 'ctf', 'other']),
    boxImage: z.string().optional(),
    draft: z.boolean().default(false),
    slug: z.string().regex(/^[a-z0-9][a-z0-9-/]*$/).optional()
  })
});

export const collections = { writeups };
