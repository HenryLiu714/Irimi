// Check every link in the built site: internal pages and #anchors must exist in dist/, and links to
// files on GitHub's main branch must name a file or directory that exists in this repository.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GITHUB } from '../site.config.mjs';

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const REPO = fileURLToPath(new URL('../../', import.meta.url));
const BLOB = new RegExp(`^${GITHUB.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/(?:blob|tree|edit)/main/([^#?]*)`);

const htmlFiles = (dir) =>
	readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
		e.isDirectory() ? htmlFiles(join(dir, e.name)) : e.name.endsWith('.html') ? [join(dir, e.name)] : [],
	);

const ids = new Map();
const idsOf = (file) => {
	if (!ids.has(file)) {
		const html = readFileSync(file, 'utf8');
		ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
	}
	return ids.get(file);
};

/** The file in dist/ that serves a site path, or null. */
const target = (path) => {
	const p = join(DIST, decodeURIComponent(path));
	if (existsSync(p) && statSync(p).isFile()) return p;
	const index = join(p, 'index.html');
	return existsSync(index) ? index : null;
};

const broken = [];
let checked = 0;
for (const file of htmlFiles(DIST)) {
	const page = '/' + posix.relative(DIST, file).replace(/index\.html$/, '');
	const html = readFileSync(file, 'utf8');
	for (const [, raw] of html.matchAll(/\shref="([^"]+)"/g)) {
		const href = raw.replace(/&amp;/g, '&');
		checked++;
		const blob = BLOB.exec(href);
		if (blob) {
			if (blob[1] && !existsSync(join(REPO, decodeURIComponent(blob[1])))) broken.push(`${page}: ${href} (no such file in the repo)`);
			continue;
		}
		if (/^[a-z]+:/i.test(href) || href.startsWith('//')) continue;
		const url = new URL(href, `http://site${page}`);
		const dest = target(url.pathname);
		if (!dest) {
			broken.push(`${page}: ${href}`);
			continue;
		}
		const frag = decodeURIComponent(url.hash.slice(1));
		if (frag && dest.endsWith('.html') && !idsOf(dest).has(frag)) broken.push(`${page}: ${href} (no #${frag})`);
	}
}

if (broken.length) {
	console.error(`${broken.length} broken links:\n  ${broken.join('\n  ')}`);
	process.exit(1);
}
console.log(`links: ${checked} checked, none broken`);
