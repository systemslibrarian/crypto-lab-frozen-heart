import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4173/crypto-lab-frozen-heart/',
    colorScheme: 'dark',
  },
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173/crypto-lab-frozen-heart/',
    reuseExistingServer: !process.env.CI,
  },
})
