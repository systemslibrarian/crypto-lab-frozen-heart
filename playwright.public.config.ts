import config from './playwright.config'
import { deploymentUrl } from './tools/verify-public-deployment.mjs'

// Keep the original full suite, test budgets, retries, theme and assertions.
// Public verification must never start or adopt a local preview server.
export default {
  ...config,
  webServer: undefined,
  reporter: [['list'], ['json', { outputFile: 'public-browser-results.json' }]],
  outputDir: 'public-browser-artifacts',
  use: { ...config.use, baseURL: deploymentUrl(process.env.PUBLIC_DEPLOYMENT_URL) },
}
