import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

export default defineConfig({
	resolve: {
		alias: {
			'@beaver-auth/core': resolve(__dirname, 'packages/core/index.ts'),
		},
	},
})
