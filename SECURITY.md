# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in ProtocolSoup, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **mason@protocolsoup.com**

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity
- **Resolution**: We will work on a fix and coordinate disclosure timing with you
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

## Advisories and CVEs

ProtocolSoup uses [GitHub repository security advisories](https://github.com/ParleSec/ProtocolSoup/security/advisories). GitHub is the CVE Numbering Authority for those records.

1. The GHSA stays **draft** until a patched release tag exists (or we deliberately disclose without a patch).
2. The GHSA **description is the CVE text**. It must describe impact, affected versions, patches, and workarounds. It must not include exploit scripts or proof-of-concept containers. Maintainer packets live under `docs/security/`.
3. Version ranges use the Go module `github.com/ParleSec/ProtocolSoup` and must include every affected **git tag**, not only the latest. GitHub ranges omit the `v` prefix (`>= 2.0.0, <= 4.1.0`).
4. Request a CVE from the draft (**Request CVE**) after the description and version range are correct. Publish the advisory only after **Patched versions** points at a real tag.
5. Public index: [Security Advisories](https://docs.protocolsoup.com/developers/security-advisories/).

Container images are not a GitHub advisory ecosystem. Name `ghcr.io/parlesec/protocolsoup-wallet` (or other images) in the advisory body so operators who pin GHCR tags are covered.

### Scope

This security policy applies to:

- The ProtocolSoup application code
- Official Docker images published to GHCR
- Documentation that could lead to insecure configurations

### Out of Scope

- Third-party dependencies (report these to the respective projects)
- Self-hosted instances with custom modifications
- Social engineering attacks

## Security Considerations

ProtocolSoup is an **educational tool** designed to demonstrate how identity protocols work. It is **not intended for production use**.

### Important Notes

1. **Mock IdP**: The built-in identity provider is for demonstration only. Do not use it as a real authentication system.

2. **Keys and Secrets**: Demo keys are generated at runtime. In production systems, use proper key management.

3. **No Production Auth**: Do not use ProtocolSoup's OAuth/OIDC/SAML implementations as production authentication providers.

4. **Network Exposure**: The default configuration is designed for local development. If exposing to a network, ensure proper security measures.

## Supported Versions

Security fixes land on the latest minor release. Older minors and previous majors are not patched.

Version tags are immutable. A released version is never retagged: Cosign signatures and SLSA provenance are attached to image digests, so rewriting a tag would orphan those attestations.

| Version | Security updates |
| ------- | ---------------- |
| Latest minor (`vX.Y.Z`) | Yes |
| Older minors of the current major | No — upgrade to the latest minor |
| Previous majors | No |

`latest` on GHCR moves with every push to `master` and is not a support commitment. Pin a `vX.Y.Z` tag or an image digest for a stable target. Pre-release tags (`vX.Y.Z-rc.N`) are not supported for security updates.
