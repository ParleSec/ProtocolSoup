import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://docs.protocolsoup.com',
  integrations: [
    starlight({
      title: 'ProtocolSoup',
      description: 'Interactive security protocol demonstrations with real implementations.',
      logo: {
        dark: './src/assets/logo-dark.svg',
        light: './src/assets/logo-light.svg',
        replacesTitle: true,
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/ParleSec/ProtocolSoup' },
      ],
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#a855f7' } },
      ],
      editLink: {
        baseUrl: 'https://github.com/ParleSec/ProtocolSoup/edit/main/docs/starlight/',
      },
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { slug: 'start-here/overview' },
            { slug: 'start-here/quickstart' },
            { slug: 'start-here/platform-at-a-glance' },
          ],
        },
        {
          label: 'Using ProtocolSoup',
          items: [
            { slug: 'using/what-you-can-do' },
            { slug: 'using/looking-glass' },
            { slug: 'using/flow-walkthroughs' },
            { slug: 'using/protocol-catalog' },
          ],
        },
        {
          label: 'Protocol Guides',
          collapsed: false,
          items: [
            {
              label: 'Federation',
              items: [
                { slug: 'protocols/oauth2' },
                { slug: 'protocols/oidc' },
                { slug: 'protocols/saml' },
              ],
            },
            {
              label: 'Provisioning',
              items: [
                { slug: 'protocols/scim' },
              ],
            },
            {
              label: 'Workload Identity',
              items: [
                { slug: 'protocols/spiffe' },
              ],
            },
            {
              label: 'Security Events',
              items: [
                { slug: 'protocols/ssf' },
              ],
            },
            {
              label: 'Verifiable Credentials',
              items: [
                { slug: 'protocols/oid4vci' },
                { slug: 'protocols/oid4vp' },
              ],
            },
          ],
        },
        {
          label: 'Deploy with GHCR',
          collapsed: true,
          items: [
            { slug: 'deploy/overview' },
            { slug: 'deploy/deployment-models' },
            { slug: 'deploy/release-and-tag-policy' },
            { slug: 'deploy/environment-variables' },
            {
              label: 'Services',
              items: [
                { slug: 'deploy/services/overview' },
                { slug: 'deploy/services/gateway' },
                { slug: 'deploy/services/federation' },
                { slug: 'deploy/services/scim' },
                { slug: 'deploy/services/ssf' },
                { slug: 'deploy/services/spiffe' },
                { slug: 'deploy/services/vc' },
                { slug: 'deploy/services/wallet' },
                { slug: 'deploy/services/frontend' },
                { slug: 'deploy/services/spire-server' },
                { slug: 'deploy/services/spire-agent' },
                { slug: 'deploy/services/spire-registration' },
              ],
            },
            { slug: 'deploy/troubleshooting' },
          ],
        },
        {
          label: 'API Reference',
          items: [
            { label: 'Explore All Endpoints', link: '/api/reference/', attrs: { target: '_self' } },
            { slug: 'api/overview' },
            { slug: 'api/integration-patterns' },
            { slug: 'api/versioning' },
          ],
        },
      ],
    }),
  ],
});
