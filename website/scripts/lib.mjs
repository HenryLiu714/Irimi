// Pure helpers for sync.mjs: turning the repo's Markdown into site pages and homepage data.
import { posix } from 'node:path';

const FENCE = /^\s*(```|~~~)/;
const LINK = /\]\(([^)\s]+)((?:\s+"[^"]*")?)\)/g;

/** Apply `fn` to each run of lines outside code fences, leaving fenced lines as they are. */
function outsideFences(markdown, fn) {
	const out = [];
	let inFence = false;
	for (const line of markdown.split('\n')) {
		if (FENCE.test(line)) {
			inFence = !inFence;
			out.push(line);
		} else {
			out.push(inFence ? line : fn(line));
		}
	}
	return out.join('\n');
}

function splitAnchor(url) {
	const i = url.indexOf('#');
	return i === -1 ? [url, ''] : [url.slice(0, i), url.slice(i)];
}

/** The site route for a repo path such as `docs/cli.md`, or null when it is not a site page. */
function siteRoute(repoPath, pages) {
	const m = /^docs\/([^/]+)\.md$/.exec(repoPath);
	if (!m) return null;
	const slug = m[1] === 'README' ? 'index' : m[1];
	if (!pages.has(slug)) return null;
	return slug === 'index' ? '/docs/' : `/docs/${slug}/`;
}

/**
 * Point every Markdown link at the page that will exist on the site: sibling docs at their routes,
 * anything else in the repo at GitHub. `from` is the directory the Markdown lives in: `docs` or `root`.
 */
export function rewriteLinks(markdown, { pages, github, from = 'docs' }) {
	const blob = `${github}/blob/main/`;
	const resolve = (url) => {
		if (url.startsWith('#')) return url;
		if (url.startsWith(blob)) {
			const [path, anchor] = splitAnchor(url.slice(blob.length));
			const route = siteRoute(path, pages);
			return route ? route + anchor : url;
		}
		if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('/')) return url;
		const [path, anchor] = splitAnchor(url);
		const repoPath = posix.normalize(posix.join(from === 'root' ? '' : from, path));
		return (siteRoute(repoPath, pages) ?? blob + repoPath) + anchor;
	};
	return outsideFences(markdown, (line) =>
		line.replace(LINK, (_, url, title) => `](${resolve(url)}${title})`),
	);
}

/** Split a doc into its title (the first `# H1`, as plain text) and the body after it. */
export function toPage(markdown, slug, opts) {
	const m = /^# (.+)$/m.exec(markdown);
	if (!m) throw new Error(`docs/${slug}.md has no "# " title`);
	const title = m[1].replace(/`/g, '').trim();
	const body = markdown.slice(m.index + m[0].length).replace(/^\n+/, '');
	return { title, body: rewriteLinks(body, opts) };
}

/** The body of the `## heading` section, up to the next `## `. Throws if there is none. */
export function section(markdown, heading) {
	const lines = markdown.split('\n');
	let inFence = false;
	let start = -1;
	for (let i = 0; i < lines.length; i++) {
		if (FENCE.test(lines[i])) inFence = !inFence;
		if (inFence || !lines[i].startsWith('## ')) continue;
		if (start !== -1) return lines.slice(start, i).join('\n');
		if (lines[i].slice(3).trim() === heading) start = i + 1;
	}
	if (start === -1) throw new Error(`README section not found: ${heading}`);
	return lines.slice(start).join('\n');
}

function cells(row) {
	return row
		.trim()
		.replace(/^\||\|$/g, '')
		.split(/(?<!\\)\|/)
		.map((c) => c.trim().replace(/\\\|/g, '|'));
}

/** The first GFM table in `markdown`, as header cells and rows of cell Markdown. */
export function parseTable(markdown) {
	const lines = markdown.split('\n');
	const at = lines.findIndex(
		(l, i) => l.trim().startsWith('|') && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1] ?? ''),
	);
	if (at === -1) throw new Error('no Markdown table found');
	const rows = [];
	for (const l of lines.slice(at + 2)) {
		if (!l.trim().startsWith('|')) break;
		rows.push(cells(l));
	}
	return { head: cells(lines[at]), rows };
}

/** The contents of the first fenced code block. Throws if there is none. */
export function firstCodeBlock(markdown) {
	const m = /^(```|~~~)[^\n]*\n([\s\S]*?)\n\1\s*$/m.exec(markdown);
	if (!m) throw new Error('no code block found');
	return m[2];
}

const escapeHtml = (s) =>
	s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Render one table cell's inline Markdown (code spans, links, bold) as HTML. */
export function inlineMarkdown(md) {
	const parts = md.split(/(`[^`]*`)/);
	return parts
		.map((part) => {
			if (part.startsWith('`') && part.endsWith('`') && part.length > 1) {
				return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
			}
			return escapeHtml(part)
				.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
				.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2">$1</a>');
		})
		.join('');
}
