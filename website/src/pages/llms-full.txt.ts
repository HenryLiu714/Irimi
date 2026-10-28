import type { APIRoute } from 'astro';
import data from '../data/readme.json';
import { asMarkdown, docsEntries, slugOf } from '../lib/docs';

// Every docs page in sidebar order, as one Markdown file for pasting into an AI tool.
export const GET: APIRoute = async () => {
	const bySlug = new Map((await docsEntries()).map((e) => [slugOf(e), e]));
	const body = data.pages
		.map((p) => bySlug.get(p.slug))
		.filter((e) => e !== undefined)
		.map(asMarkdown)
		.join('\n\n---\n\n');
	return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
