// The docs sidebar, shared by astro.config.mjs and sync.mjs. Every page sync.mjs generates must
// appear here, so a new file in docs/ fails the build instead of going missing from the site.
export const SIDEBAR = [
	{ label: 'Getting started', items: ['introduction', 'installation', 'concepts'] },
	{
		label: 'Using irimi',
		items: ['how-it-works', 'reading-the-summary', 'cli', 'sdk', 'serve-mode', 'replay', 'limitations'],
	},
	{ label: 'Reference', items: ['security', 'service-maps', 'trace-format', 'control-protocol'] },
	{ label: 'Contributing', items: ['architecture', 'adding-a-service'] },
];
