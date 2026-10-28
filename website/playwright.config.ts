import { defineConfig, devices } from '@playwright/test';

// Tests run against the built site (npm run build first), served by `astro preview`.
export default defineConfig({
	testDir: 'tests',
	fullyParallel: true,
	reporter: process.env.CI ? 'github' : 'list',
	use: { baseURL: 'http://localhost:4330', ...devices['Desktop Chrome'] },
	webServer: { command: 'npx astro preview --port 4330 --ignore-lock', url: 'http://localhost:4330/', reuseExistingServer: !process.env.CI },
});
