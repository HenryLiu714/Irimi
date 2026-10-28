import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import data from '../src/data/readme.json' with { type: 'json' };

const INSTALL = 'uv tool install --python 3.12 irimi';

/** Fail the test on any console error or uncaught exception on the page. */
function watchErrors(page: Page) {
	const errors: string[] = [];
	page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
	page.on('pageerror', (e) => errors.push(String(e)));
	return errors;
}

async function setTheme(page: Page, theme: 'dark' | 'light') {
	await page.addInitScript((t) => localStorage.setItem('starlight-theme', t), theme);
}

test('homepage explains and installs', async ({ page }) => {
	const errors = watchErrors(page);
	await page.goto('/');
	await expect(page.getByRole('heading', { level: 1 })).toContainText('Shadow mode for AI agents');
	await expect(page.locator('.hero .cmd code')).toHaveText(`$ ${INSTALL}`);
	await expect(page.locator('.terminal')).toContainText('charge_already_refunded');
	await expect(page.locator('.table--compare tbody tr')).toHaveCount(data.comparison.rows.length);
	expect(errors).toEqual([]);
});

test('copy install command', async ({ page, context }) => {
	await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await page.goto('/');
	await page.getByRole('button', { name: 'Copy install command' }).first().click();
	expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(INSTALL);
	await expect(page.locator('.hero .copy__status')).toHaveText('Copied');
});

test('copy falls back to selecting the text without clipboard access', async ({ page }) => {
	await page.addInitScript(() => {
		Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) } });
	});
	const errors = watchErrors(page);
	await page.goto('/');
	await page.getByRole('button', { name: 'Copy install command' }).first().click();
	await expect(page.locator('.hero .copy__status')).toHaveText(/Press (⌘|Ctrl\+)C/);
	expect(await page.evaluate(() => getSelection()?.toString())).toContain(INSTALL);
	expect(errors).toEqual([]);
});

test('agent tab copies prompt', async ({ page, context }) => {
	await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await page.goto('/#install');
	await page.getByRole('tab', { name: 'Ask your agent' }).click();
	await expect(page.locator('#panel-agent')).toBeVisible();
	await expect(page.locator('#panel-human')).toBeHidden();
	await page.getByRole('button', { name: 'Copy prompt' }).click();
	const copied = await page.evaluate(() => navigator.clipboard.readText());
	expect(copied).toContain('/llms.txt');
	expect(copied).toContain(INSTALL);
});

test('install tabs work from the keyboard', async ({ page }) => {
	await page.goto('/');
	await page.getByRole('tab', { name: 'Terminal' }).focus();
	await page.keyboard.press('ArrowRight');
	await expect(page.getByRole('tab', { name: 'Ask your agent' })).toBeFocused();
	await expect(page.getByRole('tab', { name: 'Ask your agent' })).toHaveAttribute('aria-selected', 'true');
});

test('theme toggle switches and persists into the docs', async ({ page }) => {
	await page.goto('/');
	await page.evaluate(() => localStorage.setItem('starlight-theme', 'dark'));
	await page.reload();
	await page.getByRole('button', { name: 'Switch to light theme' }).click();
	await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
	await page.goto('/docs/');
	await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

for (const path of ['/', '/docs/cli/', '/docs/trace-format/']) {
	test(`no horizontal overflow at 375px on ${path}`, async ({ page }) => {
		await page.setViewportSize({ width: 375, height: 800 });
		await page.goto(path);
		const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
		expect(overflow).toBeLessThanOrEqual(0);
	});
}

test('every docs page renders', async ({ page }) => {
	const errors = watchErrors(page);
	for (const p of data.pages) {
		await page.goto(p.slug === 'index' ? '/docs/' : `/docs/${p.slug}/`);
		await expect(page.locator('h1#_top')).toHaveText(p.title);
		await expect(page.locator('.sl-markdown-content')).not.toBeEmpty();
	}
	expect(errors).toEqual([]);
});

test('docs pages are served as Markdown', async ({ request }) => {
	const res = await request.get('/docs/cli.md');
	expect(res.ok()).toBe(true);
	expect(await res.text()).toMatch(/^# The irimi command\n/);
	const llms = await (await request.get('/llms.txt')).text();
	expect(llms).toMatch(/^# irimi\n\n> /);
	for (const p of data.pages) expect(llms).toContain(`/docs/${p.slug}.md)`);
});

test('mermaid renders', async ({ page }) => {
	await page.goto('/docs/how-it-works/');
	await expect(page.locator('pre.mermaid svg')).toBeVisible();
});

test('search finds shadow', async ({ page }) => {
	await page.goto('/docs/');
	await page.getByRole('button', { name: 'Search' }).click();
	await page.locator('dialog .pagefind-ui__search-input').fill('shadow');
	await expect(page.locator('.pagefind-ui__result').first()).toBeVisible();
});

test('copy page as Markdown', async ({ page, context }) => {
	await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await page.goto('/docs/concepts/');
	await page.getByRole('button', { name: 'Copy page as Markdown' }).click();
	await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
	expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^# Concepts/);
});

for (const theme of ['dark', 'light'] as const) {
	for (const path of ['/', '/docs/concepts/', '/docs/installation/', '/docs/how-it-works/']) {
		test(`axe finds no contrast or a11y violations on ${path} in ${theme}`, async ({ page }) => {
			await setTheme(page, theme);
			await page.goto(path);
			await page.waitForTimeout(1200); // let the hero animation finish
			const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
			const summary = results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).slice(0, 5).join(' | ')}`);
			expect(summary).toEqual([]);
		});
	}
}

test('copy page as Markdown without clipboard stays on the page', async ({ page }) => {
	await page.addInitScript(() => {
		Object.defineProperty(navigator, 'clipboard', {
			value: { writeText: () => Promise.reject(new Error('denied')), write: () => Promise.reject(new Error('denied')) },
		});
	});
	await page.goto('/docs/concepts/');
	await page.getByRole('button', { name: 'Copy page as Markdown' }).click();
	await expect(page.getByRole('button', { name: /Couldn.t copy/ })).toBeVisible();
	expect(new URL(page.url()).pathname).toBe('/docs/concepts/');
});

test('the docs overview has Copy page as Markdown too', async ({ page }) => {
	await page.goto('/docs/');
	await expect(page.getByRole('button', { name: 'Copy page as Markdown' })).toBeVisible();
});

test('dark is the default theme with no stored choice, even on a light OS', async ({ browser }) => {
	const context = await browser.newContext({ colorScheme: 'light' });
	const page = await context.newPage();
	for (const path of ['/', '/docs/']) {
		await page.goto(path);
		await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
	}
	await context.close();
});

test('the agent prompt points at llms.txt on the site it was copied from', async ({ page, context }) => {
	await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await page.goto('/');
	await page.getByRole('tab', { name: 'Ask your agent' }).click();
	await page.getByRole('button', { name: 'Copy prompt' }).click();
	const copied = await page.evaluate(() => navigator.clipboard.readText());
	expect(copied).toContain('http://localhost:4330/llms.txt');
	expect(copied).toMatch(/database/);
});

test('llms.txt tells an agent what to check before running', async ({ request }) => {
	const llms = await (await request.get('/llms.txt')).text();
	expect(llms).toContain('docs.astral.sh/uv');
	expect(llms).toMatch(/before running/i);
	expect(llms).toMatch(/database/i);
	// Free text sits before the first H2, per llmstxt.org; H2 sections hold link lists.
	const firstH2 = llms.indexOf('\n## ');
	expect(llms.indexOf('uv tool install')).toBeLessThan(firstH2);
});

test('homepage copy does not overclaim', async ({ page }) => {
	await page.goto('/');
	const text = await page.locator('main').innerText();
	expect(text).not.toContain('Full fakes');
	expect(text).toContain('HTTPS_PROXY and');
	await expect(page.locator('#what-irimi-does-not-catch code').first()).toBeVisible();
	await expect(page.locator('#what-irimi-does-not-catch')).toContainText('Unmapped services');
});

test.describe('at 375px', () => {
	test.use({ viewport: { width: 375, height: 800 } });

	test('the comparison shows what each approach misses without scrolling sideways', async ({ page }) => {
		await page.goto('/');
		const wrap = page.locator('.table-wrap').first();
		expect(await wrap.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0);
		const cell = page.locator('.table--compare .is-irimi td').last();
		await cell.scrollIntoViewIfNeeded();
		await expect(cell).toBeInViewport();
	});

	for (const sel of ['.try pre', '.terminal__body']) {
		test(`${sel} shows its whole text`, async ({ page }) => {
			await page.goto('/');
			const clipped = await page.locator(sel).evaluate((el) => el.scrollWidth - el.clientWidth);
			expect(clipped).toBeLessThanOrEqual(0);
		});
	}
});

test('the how-it-works diagram is drawn at a readable size', async ({ page }) => {
	await page.goto('/docs/how-it-works/');
	const label = page.locator('pre.mermaid svg .nodeLabel').first();
	await expect(label).toBeVisible();
	const height = await label.evaluate((el) => el.getBoundingClientRect().height);
	expect(height).toBeGreaterThanOrEqual(12);
});
