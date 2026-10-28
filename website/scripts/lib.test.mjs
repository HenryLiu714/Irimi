import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { firstCodeBlock, parseTable, rewriteLinks, section, toPage } from './lib.mjs';

const GITHUB = 'https://github.com/HenryLiu714/Irimi';
const opts = { pages: new Set(['cli', 'concepts', 'index']), github: GITHUB };
const README = readFileSync(new URL('../../README.md', import.meta.url), 'utf8');

test('title from h1', () => {
	const page = toPage('# The `irimi` command\n\nEvery command.\n', 'cli', opts);
	assert.equal(page.title, 'The irimi command');
	assert.equal(page.body.trim(), 'Every command.');
});

test('rewrites sibling md link with anchor', () => {
	assert.equal(rewriteLinks('[x](cli.md#exit-codes)', opts), '[x](/docs/cli/#exit-codes)');
	assert.equal(rewriteLinks('[x](concepts.md)', opts), '[x](/docs/concepts/)');
	assert.equal(rewriteLinks('[i](README.md)', opts), '[i](/docs/)');
});

test('rewrites parent link to github', () => {
	assert.equal(
		rewriteLinks('[s](../examples/sidecar/README.md)', opts),
		`[s](${GITHUB}/blob/main/examples/sidecar/README.md)`,
	);
});

test('rewrites unknown sibling to github', () => {
	assert.equal(rewriteLinks('[p](plan.md)', opts), `[p](${GITHUB}/blob/main/docs/plan.md)`);
});

test('rewrites absolute github docs link', () => {
	assert.equal(
		rewriteLinks(`[c](${GITHUB}/blob/main/docs/cli.md#exit-codes)`, opts),
		'[c](/docs/cli/#exit-codes)',
	);
	assert.equal(rewriteLinks(`[d](${GITHUB}/blob/main/docs/README.md)`, opts), '[d](/docs/)');
});

test('leaves external and anchor links alone', () => {
	const md = '[a](https://example.com/x.md) [b](#limits) [c](mailto:a@b.c)';
	assert.equal(rewriteLinks(md, opts), md);
});

test('leaves links in code fences alone', () => {
	const md = '```\n[x](cli.md)\n```\n[y](cli.md)';
	assert.equal(rewriteLinks(md, opts), '```\n[x](cli.md)\n```\n[y](/docs/cli/)');
});

test('readme-relative links resolve from the repo root', () => {
	const root = { ...opts, from: 'root' };
	assert.equal(rewriteLinks('[w](#what-irimi-does-not-catch)', root), '[w](#what-irimi-does-not-catch)');
	assert.equal(rewriteLinks('[l](LICENSE)', root), `[l](${GITHUB}/blob/main/LICENSE)`);
	assert.equal(rewriteLinks('[d](docs/cli.md)', root), '[d](/docs/cli/)');
});

test('fails loudly on missing section', () => {
	assert.throws(() => section(README, 'No Such Heading'), /README section not found: No Such Heading/);
});

test('section stops at the next h2', () => {
	const body = section('## A\none\n### sub\ntwo\n## B\nthree\n', 'A');
	assert.equal(body.trim(), 'one\n### sub\ntwo');
});

test('section ignores headings inside code fences', () => {
	const body = section('## A\n```\n## not a heading\n```\nafter\n## B\n', 'A');
	assert.match(body, /after/);
});

test('parses the README comparison table', () => {
	const table = parseTable(section(README, 'Why'));
	assert.deepEqual(table.head, ['Approach', 'Reads', 'Writes', 'What it misses']);
	assert.equal(table.rows.length, 5);
	assert.equal(table.rows.at(-1)[0], 'irimi');
});

test('parseTable fails without a table', () => {
	assert.throws(() => parseTable('no table here'), /table/);
});

test('hero output is the double refund', () => {
	const out = firstCodeBlock(section(README, 'What you get'));
	assert.match(out, /charge_already_refunded/);
	assert.doesNotMatch(out, /```/);
});

test('firstCodeBlock fails without a block', () => {
	assert.throws(() => firstCodeBlock('plain'), /code block/);
});

test('inlineMarkdown renders code, links and escapes html', async () => {
	const { inlineMarkdown } = await import('./lib.mjs');
	assert.equal(
		inlineMarkdown('`GET` <b> [below](#x) **live**'),
		'<code>GET</code> &lt;b&gt; <a href="#x">below</a> <strong>live</strong>',
	);
	assert.equal(inlineMarkdown('`a<b`'), '<code>a&lt;b</code>');
});

test('link text that is a bare filename becomes the page title', async () => {
	const { rewriteLinks: rw } = await import('./lib.mjs');
	const titles = new Map([['concepts', 'Concepts'], ['index', 'Documentation']]);
	const o = { ...opts, titles };
	assert.equal(rw('see [concepts.md](concepts.md#a).', o), 'see [Concepts](/docs/concepts/#a).');
	assert.equal(rw('[the terms](concepts.md)', o), '[the terms](/docs/concepts/)');
	assert.equal(rw('[`cli.md`](cli.md)', o), '[`cli.md`](/docs/cli/)');
});

test('toPage ignores a # line inside a code fence', () => {
	assert.throws(() => toPage('```sh\n# comment\n```\n', 'x', opts), /no "# " title/);
});

test('section errors name the heading', async () => {
	const { readmeTable, readmeCodeBlock } = await import('./lib.mjs');
	assert.throws(() => readmeTable('## A\nno table\n', 'A'), /README section "A": no Markdown table found/);
	assert.throws(() => readmeCodeBlock('## A\nplain\n', 'A'), /README section "A": no code block found/);
});
