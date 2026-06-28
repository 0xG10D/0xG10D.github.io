import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import remarkObsidianLinks from './src/plugins/remark-obsidian-links.mjs';

export default defineConfig({
  markdown: {
    processor: unified({
      remarkPlugins: [remarkObsidianLinks]
    }),
    syntaxHighlight: {
      type: 'shiki'
    },
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark'
      },
      defaultColor: false,
      langs: ['bash', 'python', 'powershell', 'javascript', 'typescript', 'json', 'html', 'css'],
      wrap: true
    }
  }
});
