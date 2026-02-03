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

| Version | Supported |
| ------- | --------- |
| Latest  | ✅        |
| < 1.0   | ❌        |

We only provide security updates for the latest version. Please keep your installation up to date.
