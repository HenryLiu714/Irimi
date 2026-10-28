// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// The one place the public URL lives; llms.txt and the agent install prompt read it from here.
export const SITE = 'https://irimi.dev';
export const GITHUB = 'https://github.com/HenryLiu714/Irimi';

export default defineConfig({
	site: SITE,
	integrations: [
		starlight({
			title: 'irimi',
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB }],
		}),
	],
});
