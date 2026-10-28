// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import remarkMermaid from './src/plugins/remark-mermaid.mjs';
import { GITHUB, SITE } from './site.config.mjs';
import { SIDEBAR } from './scripts/sidebar.mjs';

export default defineConfig({
	site: SITE,
	markdown: { remarkPlugins: [remarkMermaid] },
	integrations: [
		starlight({
			title: 'irimi',
			logo: { src: './public/favicon.svg', alt: '' },
			description: 'Shadow mode for AI agents: reads are real, writes are faked, and reads see the writes.',
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB }],
			customCss: ['@fontsource-variable/geist', '@fontsource-variable/geist-mono', './src/styles/theme.css'],
			expressiveCode: { themes: ['github-dark-default', 'github-light-default'] },
			components: {
				PageTitle: './src/components/PageTitle.astro',
				MarkdownContent: './src/components/MarkdownContent.astro',
				ThemeProvider: './src/components/ThemeProvider.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
			},
			sidebar: [
				{ label: 'Overview', link: '/docs/' },
				...SIDEBAR.map((g) => ({ label: g.label, items: g.items.map((slug) => `docs/${slug}`) })),
			],
		}),
	],
});
