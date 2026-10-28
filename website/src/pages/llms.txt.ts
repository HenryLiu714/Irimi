import type { APIRoute } from 'astro';
import data from '../data/readme.json';
import { GITHUB, SITE } from '../../site.config.mjs';

// An index for AI tools, per https://llmstxt.org: what irimi is, how to install it, and every page.
export const GET: APIRoute = () => {
	const lines = [
		'# irimi',
		'',
		`> ${data.tagline}`,
		'',
		'irimi is a local proxy you put between an AI agent and the services it calls. Reads pass through to the real service; writes over HTTP(S) are answered with a realistic fake success, and later reads are edited to show them. At the end it prints every write the agent would have made, and which the real service would have refused.',
		'',
		'## Install and run',
		'',
		'Requires Python 3.12+ (a standard, not free-threaded, build) on macOS or Linux.',
		'',
		'```',
		'uv tool install --python 3.12 irimi    # or: pipx install --python python3.12 irimi',
		'irimi init                             # generates a local CA in ~/.irimi/ca/',
		'irimi shadow -- <command that runs the agent>',
		'```',
		'',
		'`irimi shadow` starts the proxy, runs the command with HTTPS_PROXY and the CA set, and prints a summary when it exits. Only traffic sent through the proxy is shadowed: read the Limitations page before relying on it.',
		'',
	];
	let group: string | null | undefined;
	for (const page of data.pages) {
		if (page.group !== group) {
			if (group !== undefined) lines.push('');
			group = page.group;
			lines.push(`## ${group ?? 'Docs'}`, '');
		}
		lines.push(`- [${page.title}](${SITE}/docs/${page.slug}.md): ${page.description}`);
	}
	lines.push('', '## Optional', '', `- [All docs in one file](${SITE}/llms-full.txt)`, `- [Source code](${GITHUB})`, '');
	return new Response(lines.join('\n'), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
