import type { APIRoute, GetStaticPaths } from 'astro';
import type { CollectionEntry } from 'astro:content';
import { asMarkdown, docsEntries, slugOf } from '../../lib/docs';

export const getStaticPaths = (async () =>
	(await docsEntries()).map((entry) => ({ params: { slug: slugOf(entry) }, props: { entry } }))) satisfies GetStaticPaths;

export const GET: APIRoute<{ entry: CollectionEntry<'docs'> }> = ({ props }) =>
	new Response(asMarkdown(props.entry), { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
