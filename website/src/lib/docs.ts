import { getCollection, type CollectionEntry } from 'astro:content';

/** The URL path segment of a docs entry: `cli` for `docs/cli`, `index` for the docs index. */
export const slugOf = (entry: CollectionEntry<'docs'>) =>
	entry.id === 'docs' ? 'index' : entry.id.replace(/^docs\//, '');

/** A docs page as standalone Markdown, with its title restored as the `# H1`. */
export const asMarkdown = (entry: CollectionEntry<'docs'>) =>
	`# ${entry.data.title}\n\n${(entry.body ?? '').trim()}\n`;

export const docsEntries = async () =>
	(await getCollection('docs')).filter((e) => e.id === 'docs' || e.id.startsWith('docs/'));
