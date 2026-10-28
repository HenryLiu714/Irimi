// Generate the docs pages and homepage data from ../docs/*.md and ../README.md.
// Run before every dev and build; the output is gitignored. Fails loudly when the source changes shape.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { GITHUB } from '../site.config.mjs';
import { inlineMarkdown, readmeCodeBlock, readmeTable, rewriteLinks, section, toPage } from './lib.mjs';
import { SIDEBAR } from './sidebar.mjs';

const REPO = new URL('../../', import.meta.url);
const OUT = new URL('../src/content/docs/docs/', import.meta.url);
const DATA = new URL('../src/data/', import.meta.url);

const read = (path) => readFileSync(new URL(path, REPO), 'utf8');
const readme = read('README.md');
const docFiles = readdirSync(new URL('docs/', REPO)).filter((f) => f.endsWith('.md'));
const slugOf = (file) => (file === 'README.md' ? 'index' : file.slice(0, -3));
const pages = new Set([...docFiles.map(slugOf), 'introduction', 'installation']);
const titleOf = (md) => /^# (.+)$/m.exec(md)?.[1].replace(/`/g, '').trim();
const titles = new Map(docFiles.map((f) => [slugOf(f), titleOf(read(`docs/${f}`))]));
titles.set('index', 'Documentation');
const opts = { pages, github: GITHUB, titles };

// One-line descriptions, from the docs index's "- [Title](page.md): description." list.
const descriptions = new Map(
	[...read('docs/README.md').matchAll(/^- \[[^\]]+\]\(([^)]+)\.md\): (.+(?:\n {2,}\S.*)*)/gm)].map((m) => [
		m[1],
		m[2].replace(/\s*\n\s*/g, ' '),
	]),
);

const README_PAGES = {
	introduction: {
		title: 'Introduction',
		description: 'What irimi is, what you get from a run, and how it compares.',
		sections: ['What you get', 'Why', 'What irimi does not catch', 'How it works'],
	},
	installation: {
		title: 'Installation & quickstart',
		description: 'Install irimi, shadow a first write, then run an agent under it.',
		sections: ['Quickstart', 'What is supported', 'CLI', 'Troubleshooting'],
	},
};

/** The README's opening paragraphs: everything between the italic tagline and the first `## `. */
function readmeIntro() {
	const m = /^\*([^*\n]+)\*\s*$([\s\S]*?)^## /m.exec(readme);
	if (!m) throw new Error('README tagline or opening paragraphs not found');
	return { tagline: m[1].trim(), intro: m[2].trim() };
}

const frontmatter = (fields) =>
	`---\n${Object.entries(fields)
		.map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
		.join('\n')}\n---\n\n`;

const written = [];
function writePage(slug, { title, description, body, source }) {
	const editUrl = `${GITHUB}/edit/main/${source}`;
	writeFileSync(new URL(`${slug}.md`, OUT), frontmatter({ title, description, editUrl }) + body);
	written.push({ slug, title, description, source });
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
mkdirSync(DATA, { recursive: true });

for (const file of docFiles) {
	const slug = slugOf(file);
	const { title, body } = toPage(read(`docs/${file}`), slug, opts);
	const description = descriptions.get(file.slice(0, -3)) ?? (slug === 'index' ? 'Every page, by audience.' : title);
	writePage(slug, { title: slug === 'index' ? 'Documentation' : title, description, body, source: `docs/${file}` });
}

const { tagline, intro } = readmeIntro();
for (const [slug, page] of Object.entries(README_PAGES)) {
	const parts = page.sections.map((h) => `## ${h}\n\n${section(readme, h).trim()}`);
	if (slug === 'introduction') parts.unshift(`*${tagline}*\n\n${intro}`);
	const body = rewriteLinks(parts.join('\n\n'), { ...opts, from: 'root' });
	writePage(slug, { ...page, body, source: 'README.md' });
}

const inSidebar = new Set(SIDEBAR.flatMap((g) => g.items));
const missing = written.map((p) => p.slug).filter((s) => s !== 'index' && !inSidebar.has(s));
if (missing.length) throw new Error(`docs pages missing from scripts/sidebar.mjs: ${missing.join(', ')}`);
const stale = [...inSidebar].filter((s) => !pages.has(s));
if (stale.length) throw new Error(`scripts/sidebar.mjs names pages that do not exist: ${stale.join(', ')}`);

// Homepage data. Links in table cells are rewritten from the repo root, then rendered to HTML.
const table = (heading) => {
	const t = readmeTable(rewriteLinks(readme, { ...opts, from: 'root' }), heading);
	return { head: t.head, rows: t.rows.map((r) => r.map(inlineMarkdown)) };
};
const order = SIDEBAR.flatMap((g) => g.items.map((slug) => ({ slug, group: g.label })));
const bySlug = new Map(written.map((p) => [p.slug, p]));
const data = {
	tagline,
	heroOutput: readmeCodeBlock(readme, 'What you get'),
	comparison: table('Why'),
	services: table('What is supported'),
	pages: [{ slug: 'index', group: null, ...bySlug.get('index') }, ...order.map((o) => ({ ...o, ...bySlug.get(o.slug) }))],
};
writeFileSync(new URL('readme.json', DATA), JSON.stringify(data, null, '\t') + '\n');
console.log(`sync: ${written.length} docs pages, homepage data from README.md`);
