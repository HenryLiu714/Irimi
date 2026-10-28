import { mkdirSync, writeFileSync } from 'node:fs';
mkdirSync('src/content/docs/docs', { recursive: true });
writeFileSync('src/content/docs/docs/index.md', '---\ntitle: Docs\n---\nPlaceholder.\n');
