/// <reference types="vitest" />
import { defineConfig } from 'vite'

export default defineConfig({
  base: '/crypto-lab-frozen-heart/',
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
