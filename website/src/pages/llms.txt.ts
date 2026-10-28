import type { APIRoute } from 'astro';
import data from '../data/readme.json';
import { GITHUB, SITE } from '../../site.config.mjs';

// An index for AI tools, per https://llmstxt.org: free text before the first H2, then link lists.
export const GET: APIRoute = () => {
	const lines = [
		'# irimi',
		'',
		`> ${data.tagline}`,
		'',
		'irimi is a local proxy you put between an AI agent and the services it calls. Reads pass through to the real service; writes over HTTP(S) that go through irimi are answered with a fake success, and for Stripe and Slack later reads are edited to show them. At the end it prints every write the agent sent through the proxy, and, where irimi can check, which the real service would have refused.',
		'',
		'Install and run (Python 3.12+, a standard not free-threaded build, on macOS or Linux; needs uv, https://docs.astral.sh/uv/getting-started/installation/):',
		'',
		'```',
		'uv tool install --python 3.12 irimi    # or: pipx install --python python3.12 irimi',
		'uv tool update-shell                   # only if `irimi` is not found afterwards',
		'irimi init                             # generates a local CA in ~/.irimi/ca/',
		'irimi shadow -- <command that runs the agent>',
		'```',
		'',
		'`irimi shadow` starts the proxy, runs the command with HTTPS_PROXY and the CA set, and prints a summary when it exits.',
		'',
		'Before running an agent under irimi, check these with the user:',
		'',
		'- Only HTTP(S) through the proxy is faked. Database, file, gRPC, WebSocket and queue writes happen for real; stop and ask before running an agent that makes them, or point them at scratch data.',
		'- Reads and LLM calls are real, made with the agent\'s real credentials, and billed.',
		'- Run the agent with its own Python (a venv or uv), not macOS\'s /usr/bin/python3. If the summary reports connections that "failed TLS", the client ignores irimi\'s CA; see the How it works page, "What the child gets".',
		'- Every response irimi made carries an `Irimi-Answered-By` header; a write with no line in the summary went to the real service.',
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
