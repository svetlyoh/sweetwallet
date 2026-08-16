import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: {
				configPath: './wrangler.jsonc'
			},
			miniflare: {
				bindings: {
					KEYLINK_PIN_PEPPER: 'test-only-keylink-pin-pepper-64d8b9f1'
				}
			}
		})
	],
	test: {
		include: ['test/keylink-worker.test.mjs']
	}
});
