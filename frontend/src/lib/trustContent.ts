import { TRUST_LAST_REVIEWED } from '@/lib/trust'

export type TrustLink = { href: string; label: string }

export type TrustText = string | TrustLink

export type TrustBlock =
  | { type: 'p'; parts: TrustText[] }
  | { type: 'ul'; items: string[] }
  | { type: 'pre'; code: string }
  | { type: 'table'; headers: string[]; rows: string[][] }

export type TrustSection = {
  id: string
  title: string
  blocks: TrustBlock[]
}

export const GATEWAY_IMAGE_DIGEST =
  'ghcr.io/parlesec/protocolsoup-gateway@sha256:e5d429a97ac1c70d32c89f41cb452d817d835fb725a537b67ab0cceb1c0ea30d'

export const GATEWAY_ATTESTATION_VERIFY = `gh attestation verify oci://${GATEWAY_IMAGE_DIGEST} --repo ParleSec/ProtocolSoup --format json`

export const GATEWAY_COSIGN_VERIFY = `cosign verify --certificate-identity-regexp 'https://github.com/ParleSec/ProtocolSoup/.github/workflows/ghcr-publish.yml@refs/heads/master' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' ${GATEWAY_IMAGE_DIGEST}`

export const GATEWAY_SBOM_INSPECT =
  "docker buildx imagetools inspect ghcr.io/parlesec/protocolsoup-gateway:latest --format '{{ json .SBOM }}'"

const OIDF_IMPLEMENTATIONS =
  'https://openid.net/certification/certified-openid-connect-implementations/'

function p(...parts: TrustText[]): TrustBlock {
  return { type: 'p', parts }
}

function ul(items: string[]): TrustBlock {
  return { type: 'ul', items }
}

function pre(code: string): TrustBlock {
  return { type: 'pre', code }
}

function table(headers: string[], rows: string[][]): TrustBlock {
  return { type: 'table', headers, rows }
}

export const TRUST_SECTIONS: TrustSection[] = [
  {
    id: 'scope',
    title: 'Scope',
    blocks: [
      p(
        'This page describes the hosted instance at protocolsoup.com, wallet.protocolsoup.com, docs.protocolsoup.com, and protocolsoup-spire. Compute is Fly.io in syd. It does not describe a self-hosted deployment you run yourself.',
      ),
      p(
        'SECURITY.md states ProtocolSoup is an educational tool and is not intended for production authentication. SHOWCASE_MOCK_IDP is true on the protocolsoup Fly app. Do not use this instance as a production identity provider, and do not send production employee data to hosted SCIM.',
      ),
    ],
  },
  {
    id: 'trust-boundary',
    title: 'Trust boundary',
    blocks: [
      p(
        'A visitor HTTPS request is terminated at Cloudflare (DNS and HTTP proxy; not Cloudflare Pages), then forwarded to Fly. Public responses included via: 1.1 fly.io. cdn-cgi/trace on 2026-08-20 showed gateway=off for protocolsoup.com, wallet, and docs. Cloudflare Access is not bound to those hostnames.',
      ),
      p(
        'Edge TLS is a Google Trust Services WE1 certificate issued through Cloudflare. Cloudflare zone setting min_tls_version is 1.2. ssl is strict (Full Strict). always_use_https is on. Captured handshakes: TLS 1.3 by default (HTTP/2) and TLS 1.2 accepted. Cloudflare security_header.strict_transport_security.enabled is false; public responses had no Strict-Transport-Security header.',
      ),
      p('Parties on the request or supply path, as captured:'),
      table(
        ['Party', 'Role'],
        [
          [
            'Fly.io',
            'Application hosting: protocolsoup, protocolsoup-wallet, protocolsoup-docs, protocolsoup-spire (one machine each, syd)',
          ],
          [
            'Cloudflare',
            'DNS and HTTP proxy, Pro Website plan. Cloudflare Managed Ruleset is present and not enabled. One custom skip: GET wallet.protocolsoup.com/health skips Super Bot Fight. Super Bot Fight JS detections on; definitely-automated traffic set to allow',
          ],
          [
            'GitHub / GHCR',
            'Source, CI, and the gateway image',
          ],
          [
            'Sigstore (Fulcio, Rekor)',
            'Keyless signing; the Rekor transparency log is public by design',
          ],
          [
            'Fly Redis (Upstash)',
            'App protocolsoup-vc-cert-replay in syd, Pay-as-you-go, eviction disabled. DPoP and private_key_jwt jti replay records only',
          ],
        ],
      ),
      p(
        'Proton Mail appears in DNS (SPF, verification, DKIM CNAMEs) and is not on the HTTPS path. Umami is not deployed. Google Trust Services issues the edge certificate via Cloudflare; it is not a separate host.',
      ),
    ],
  },
  {
    id: 'scanner-alerts',
    title: 'Scanner alerts',
    blocks: [
      p(
        'Protocol endpoints on this host are intentionally real (OIDC, SCIM, SSF, and others). A scanner that treats any of those as an unexpected service is looking at demonstration protocol surfaces, not an accidental exposure of an internal admin API.',
      ),
      p(
        'Unauthenticated GET and POST /scim/v2/Users returned HTTP 401 with a SCIM error body. SCIM_API_TOKEN is set on the protocolsoup Fly app. Unauthenticated SCIM writes were not accepted.',
      ),
      p(
        'https://protocolsoup.com:9091/metrics and http://protocolsoup.com:9091/metrics timed out. GET /metrics on 443 returned a Next.js HTML 404, not Prometheus text.',
      ),
      p(
        'HEAD /.well-known/openid-configuration returned 404 Next.js HTML. GET of the same path returned 200 JSON. HEAD /oidc/.well-known/openid-configuration returned 405 with Allow: GET. Discovery checks that use HEAD will misread this host.',
      ),
      p(
        'HTML and CSS fetched on 2026-08-20 loaded first-party /_next assets. Cloudflare NEL (report-to / nel) may contact a.nel.cloudflare.com from a supporting browser. That was not verified in a browser network panel. Wallet CSS loads same-origin woff2 fonts. The protocolsoup.com homepage CSS had no @font-face.',
      ),
    ],
  },
  {
    id: 'supply-chain',
    title: 'Supply chain',
    blocks: [
      p(
        'Pinned image at capture: ',
        GATEWAY_IMAGE_DIGEST,
        '. Attested source commit d2c98f5eca26c0bd009afa4ecd97b8400b9c2ca1. Workflow .github/workflows/ghcr-publish.yml@refs/heads/master. Issuer https://token.actions.githubusercontent.com. Predicate type https://slsa.dev/provenance/v1. Rekor timestamp 2026-08-20T21:04:39+10:00.',
      ),
      p(
        'Verify with --format json. The same command without --format json exited 0 and printed nothing in this capture.',
      ),
      pre(GATEWAY_ATTESTATION_VERIFY),
      p(
        'cosign verify of the same digest succeeded on 2026-08-20 (cosign v2.5.3). Subject and issuer match the attestation above.',
      ),
      pre(GATEWAY_COSIGN_VERIFY),
      p('SBOM attached to the image (SPDX-2.3, Syft / BuildKit). linux/amd64: 39 packages, 204 files.'),
      pre(GATEWAY_SBOM_INSPECT),
      p(
        'CI uploads Trivy CRITICAL,HIGH findings to GitHub code scanning with exit-code 0 (reported, not blocking). Snyk npm, Go, and Code upload SARIF; those scan steps use continue-on-error. A PEM private-key CI check is present. Unauthenticated GET of code-scanning alerts returned 401. https://github.com/ParleSec/ProtocolSoup/security/code-scanning returned 404. Alerts are not visible to anonymous readers.',
      ),
    ],
  },
  {
    id: 'hosted-instance',
    title: 'Hosted instance',
    blocks: [
      p(
        'protocolsoup.com HTML and API GET responses included X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, and X-XSS-Protection: 1; mode=block. Those four are set by Go middleware and were present on origin. Wallet and docs HTML did not serve them; Cloudflare did not add them. The capture did not include Content-Security-Policy, Strict-Transport-Security, or Permissions-Policy on those responses.',
      ),
      p(
        'SCIM requires an Authorization header. Unauthenticated GET and POST /scim/v2/Users returned 401.',
      ),
      table(
        ['Store', 'Retention'],
        [
          ['SCIM users and groups', '24h default (SCIM_RETENTION unset). Hourly ticker in code. Sweep log line not seen in the captured fly logs window.'],
          ['Looking Glass sessions', 'In-memory. 30 minutes idle / 4 hours absolute.'],
          ['OID4VP request sessions', 'Purged: 5 minute request TTL plus 10 minute grace, 2 minute ticker.'],
          ['SSF stream state (/data/ssf)', 'No age-based purge found.'],
          ['OP signing keys (/data/keys) and mdoc PKI (/data/mdoc)', 'Persistent by design.'],
          ['DPoP / private_key_jwt replay (Redis)', 'DPoP jti until iat+60s; private_key_jwt jti until assertion exp+60s.'],
        ],
      ),
      p(
        'SCIM 24h does not cover SSF, keys, or mdoc PKI. The site ran no first-party analytics (no Umami, gtag, or Plausible in homepage or wallet HTML). Cloudflare NEL is not first-party analytics.',
      ),
      p(
        'Each of the four Fly apps ran one machine in syd. There is no second replica and no SLA. status.protocolsoup.com did not resolve. Volume protocolsoup_data: 1 GB, syd, encrypted, scheduled snapshots, snapshot retention 5 days.',
      ),
    ],
  },
  {
    id: 'conformance',
    title: 'Conformance',
    blocks: [
      p(
        'OIDF certified implementations page (captured 2026-08-20): ',
        { href: OIDF_IMPLEMENTATIONS, label: 'openid.net/certification/certified-openid-connect-implementations' },
        '. ProtocolSoup was not present in the HTML of “Certified OpenID Provider Libraries” or “Certified OpenID Provider Servers and Services”. The OP profiles table was not readable (empty AJAX body). This page does not claim OIDC OP certification.',
      ),
      p(
        'OIDF heading “Certified OID4VP software” listed ProtocolSoup v4.1.0 (Certified by ProtocolSoup, Go, Apache License 2.0) with these OID4VCI Wallet profiles:',
      ),
      ul([
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet sd_jwt_vc issuer_initiated by_reference',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet mdoc issuer_initiated by_value',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet mdoc issuer_initiated by_reference',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet sd_jwt_vc issuer_initiated by_value',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet sd_jwt_vc wallet_initiated by_value',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Wallet mdoc wallet_initiated by_value',
      ]),
      p(
        'OIDF heading “Certified OID4VCI software” listed ProtocolSoup v4.0.0 with mixed OID4VP wallet/verifier and OID4VCI issuer profiles:',
      ),
      ul([
        'OID4VP-1.0-FINAL+HAIP-1.0-FINAL Wallet iso_mdl direct_post.jwt',
        'OID4VP-1.0-FINAL+HAIP-1.0-FINAL Wallet sd_jwt_vc direct_post.jwt',
        'OID4VP-1.0-FINAL+HAIP-1.0-FINAL Verifier sd_jwt_vc direct_post.jwt',
        'OID4VP-1.0-FINAL+HAIP-1.0-FINAL Verifier iso_mdl direct_post.jwt',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Issuer mdoc issuer_initiated',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Issuer sd_jwt_vc wallet_initiated',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Issuer mdoc wallet_initiated',
        'OID4VCI-1.0-FINAL+HAIP-1.0-FINAL Issuer sd_jwt_vc issuer_initiated',
      ]),
      p(
        'Those headings do not match the profile names underneath them. The listing had versions, not certification dates. OID4VCI Wallet profiles are listed at v4.1.0.',
      ),
    ],
  },
  {
    id: 'vulnerability-disclosure',
    title: 'Vulnerability disclosure',
    blocks: [
      p(
        'Contact ',
        { href: 'mailto:mason@protocolsoup.com', label: 'mason@protocolsoup.com' },
        '. Do not open a public GitHub issue. Acknowledgment target: within 48 hours. Fix and disclosure timing are coordinated with the reporter. There is no numbered day count beyond acknowledgment.',
      ),
      p('In scope: the ProtocolSoup application code; official Docker images published to GHCR; documentation that could lead to insecure configurations.'),
      p(
        'Out of scope: third-party dependencies (report those to the respective projects); self-hosted instances with custom modifications; social engineering attacks.',
      ),
      p(
        'Credit: we will credit you in the security advisory unless you prefer to remain anonymous. Unauthenticated GitHub security advisories for ParleSec/ProtocolSoup were an empty list on 2026-08-20.',
      ),
      p(
        'Machine-readable contact: ',
        { href: '/.well-known/security.txt', label: '/.well-known/security.txt' },
        '.',
      ),
    ],
  },
  {
    id: 'governance',
    title: 'Governance',
    blocks: [
      p(
        'Public repository ',
        { href: 'https://github.com/ParleSec/ProtocolSoup', label: 'github.com/ParleSec/ProtocolSoup' },
        '. OIDF listed the software as Apache License 2.0. This page was last reviewed ',
        TRUST_LAST_REVIEWED,
        '.',
      ),
    ],
  },
  {
    id: 'limitations',
    title: 'Limitations',
    blocks: [
      p(
        'This is not a production identity provider. SECURITY.md says the project is an educational tool and is not intended for production use. The hosted app has SHOWCASE_MOCK_IDP=true.',
      ),
      p(
        'Each Fly app is a single machine in one region. A region or host failure is an outage. There is no published SLA and no status URL.',
      ),
      p(
        'Hosted SCIM is for demonstration records. Authentication is required. Default retention is 24 hours. Do not send real employee directories here. SSF stream state has no age-based purge. Signing keys and mdoc PKI persist on volume.',
      ),
    ],
  },
]
