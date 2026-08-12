import { defineConfig } from 'vitepress';

// THIS FILE IS THE ONE THAT DISAPPEARS.
//
// A bare `config.js` in a global gitignore silently excluded this from
// featureboard's first push. VitePress builds fine without it, so the site
// deployed with no nav and the workflow reported success. Nothing caught it.
// `npm run check-tracked` is what catches it now — see standards/traps.md #1.

export default defineConfig({
  title: 'oauth-host',
  description: 'OAuth 2.1 + OIDC authorization server for Express/Mongoose apps.',
  base: '/oauth-host/',
  lastUpdated: true,
  cleanUrls: true,
  head: [
    ['meta', { name: 'theme-color', content: '#2563eb' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'oauth-host' }],
    ['meta', { property: 'og:description', content: 'OAuth 2.1 + OIDC authorization server for Express/Mongoose apps.' }],
  ],
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Reference', link: '/reference/factory' },
      { text: 'GitHub', link: 'https://github.com/JeffJassky/oauth-host' },
    ],
    // Every link below must resolve to a real page — VitePress fails the build
    // on a dead link, which is the feature. traps #13.
    sidebar: {
      '/guide/': [
        {
          text: 'Getting started',
          items: [
            { text: 'Introduction', link: '/guide/introduction' },
            { text: 'Quickstart', link: '/guide/quickstart' },
            { text: 'Configuration', link: '/guide/configuration' },
          ],
        },
        {
          text: 'Integrating',
          items: [
            { text: 'The consent screen', link: '/guide/consent-screen' },
            { text: 'Adapters', link: '/guide/adapters' },
            { text: 'MCP connectors', link: '/guide/mcp' },
            { text: 'Client ID metadata', link: '/guide/cimd' },
            { text: 'Data model', link: '/guide/data-model' },
          ],
        },
        {
          text: 'Operating',
          items: [
            { text: 'Security', link: '/guide/security' },
            { text: 'Account deletion', link: '/guide/account-deletion' },
            { text: 'Testing', link: '/guide/testing' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'API',
          items: [
            { text: 'createOAuthHost', link: '/reference/factory' },
            { text: 'Routers', link: '/reference/routers' },
            { text: 'protect()', link: '/reference/protect' },
            { text: 'Admin API', link: '/reference/admin-api' },
            { text: 'Models', link: '/reference/models' },
          ],
        },
        {
          text: 'Types',
          items: [{ text: 'Types & payloads', link: '/reference/types' }],
        },
      ],
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/JeffJassky/oauth-host' }],
    editLink: {
      pattern: 'https://github.com/JeffJassky/oauth-host/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Jeff Jassky',
    },
    search: { provider: 'local' },
  },
});
