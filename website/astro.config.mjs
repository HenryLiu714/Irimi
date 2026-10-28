// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { GITHUB, SITE } from './site.config.mjs';
import { SIDEBAR } from './scripts/sidebar.mjs';

export default defineConfig({
	site: SITE,
	integrations: [
		starlight({
			title: 'irimi',
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB }],
			sidebar: [
				{ label: 'Overview', link: '/docs/' },
				...SIDEBAR.map((g) => ({ label: g.label, items: g.items.map((slug) => `docs/${slug}`) })),
			],
		}),
	],
});
