/**
 * SAML 2.0 — Parameter Explainers
 *
 * XML-based SSO. Parameter names use PascalCase per the SAML wire format
 * (`SAMLResponse`, `RelayState`, `NameID`, etc.). Attack surface is
 * fundamentally different from JSON-based protocols: XML Signature
 * Wrapping (XSW), Golden SAML, XXE, comment injection, signature
 * stripping all live here.
 */

import type { ParameterExplainer } from './index'

export const SAML_EXPLAINERS: Record<string, ParameterExplainer> = {
  SAMLResponse: {
    purpose:
      'Base64-encoded XML SAML Response containing one or more Assertions ' +
      'about the authenticated user. Posted by the IdP to the SP\'s ' +
      'Assertion Consumer Service URL after successful authentication. The ' +
      'cryptographic deliverable of the entire SP-Initiated SSO flow. ' +
      'SAML\'s XML model is large enough that the parser and the signature ' +
      'verifier can disagree about which bytes matter — and every ' +
      'disagreement is a potential auth bypass.',
    attacks: [
      {
        id: 'xml-signature-wrapping',
        name: 'XML Signature Wrapping (XSW)',
        scenario:
          'The IdP signs a Response containing a legitimate Assertion. ' +
          'Mallory intercepts it, embeds a *second* malicious Assertion ' +
          '(with her chosen NameID, attributes, audience) into the same ' +
          'XML document at a different location, and forwards it to the ' +
          'SP. The signature verifier follows ID/URI references and ' +
          'validates the legitimate Assertion — signature checks pass. ' +
          'The SP\'s business logic, however, walks the DOM and consumes ' +
          'the *first* Assertion it finds (Mallory\'s). Multiple 2024 ' +
          'high-severity CVEs: Ruby-SAML CVE-2024-45409 (CVSS 9.8, full ' +
          'impersonation, GitLab impacted); GitHub Enterprise Server ' +
          'CVE-2024-6800; HaloITSM CVE-2024-6202.',
        impact:
          'Authentication bypass with full identity impersonation, with no ' +
          'broken cryptography. PortSwigger\'s 2026 "Fragile Lock" ' +
          'research is still discovering new XSW bypasses against ' +
          'widely-deployed libraries.',
      },
      {
        id: 'signature-stripping',
        name: 'Signature stripping',
        scenario:
          'Remove the `<Signature>` element entirely from the Response. ' +
          'The verifier returns "no signature to check" instead of ' +
          'failing. SP processes the Assertion as if signed.',
        impact:
          'Authentication bypass via missing signature treated as absent ' +
          'rather than required.',
      },
      {
        id: 'xxe-in-saml',
        name: 'XXE during XML parsing',
        scenario:
          'DTDs are enabled by default in many XML parsers. An attacker ' +
          'submits a SAML Response (or metadata) containing ' +
          '`<!ENTITY xxe SYSTEM "file:///etc/passwd">` and the entity ' +
          'expansion reads arbitrary files. CVE-2024-52806 in ' +
          'simplesamlphp/saml2 is a recent example.',
        impact:
          'File disclosure / SSRF before signature verification even runs.',
      },
      {
        id: 'comment-injection-saml-response',
        name: 'Comment injection',
        scenario:
          '`<NameID>admin@victim.com<!--x-->@evil.com</NameID>` — ' +
          'signature canonicalisation (C14N) strips the comment and ' +
          'computes a hash that the verifier accepts; application parsing ' +
          'reads the un-canonicalised value and gets a different identity.',
        impact:
          'Wrong-user authentication with valid signature — application ' +
          'and verifier disagree on what the Assertion says.',
      },
    ],
    mitigations: [
      {
        action:
          'Verify signature *first*, then operate only on the verified ' +
          'subtree — do not re-traverse the DOM after verification.',
        mitigates: ['xml-signature-wrapping'],
      },
      {
        action:
          'Reject Responses containing more than one Assertion or ' +
          'unexpected sibling nodes.',
        mitigates: ['xml-signature-wrapping'],
      },
      {
        action:
          'Treat absence of signature as failure, not as "nothing to ' +
          'verify". Require signed Assertions or signed Response per SP ' +
          'metadata configuration.',
        mitigates: ['signature-stripping'],
      },
      {
        action:
          'Disable DTD / external-entity processing in the XML parser ' +
          '(set FEATURE_SECURE_PROCESSING, disallow doctype-decl, etc.).',
        mitigates: ['xxe-in-saml'],
      },
      {
        action:
          'Use battle-tested SAML libraries patched against ' +
          'comment-injection (post-Duo 2018) — never hand-roll XML ' +
          'canonicalisation.',
        mitigates: [
          'comment-injection-saml-response',
          'xml-signature-wrapping',
        ],
      },
    ],
    references: [
      {
        label: 'PortSwigger — The Fragile Lock: Novel XSW Bypasses (2026)',
        href: 'https://portswigger.net/research/the-fragile-lock',
      },
      {
        label: 'CVE-2024-45409 (Ruby-SAML, CVSS 9.8)',
        href: 'https://nvd.nist.gov/vuln/detail/CVE-2024-45409',
      },
      {
        label: 'USENIX 2012 — On Breaking SAML: Be Whoever You Want to Be',
        href: 'https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf',
      },
      {
        label: 'CVE-2024-52806 (simplesamlphp/saml2 XXE)',
        href: 'https://security.snyk.io/vuln/SNYK-PHP-SIMPLESAMLPHPSAML2-8449140',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6 (Common Threats and Countermeasures)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  SAMLRequest: {
    purpose:
      'Base64-encoded (and DEFLATE-compressed for HTTP-Redirect binding) ' +
      'XML AuthnRequest or LogoutRequest the SP sends to the IdP. ' +
      'Specifies the SP\'s identity (Issuer), where to deliver the response ' +
      '(AssertionConsumerServiceURL), session controls (ForceAuthn, ' +
      'IsPassive), and NameID format preferences.',
    attacks: [
      {
        id: 'authnrequest-forgery-session-fixation',
        name: 'AuthnRequest forgery for session fixation',
        scenario:
          'A SAML deployment that does not require signed AuthnRequests ' +
          '(`AuthnRequestsSigned=false` in IdP-side metadata about the ' +
          'SP) accepts any request claiming to be from the SP. Mallory ' +
          'crafts an AuthnRequest with `AssertionConsumerServiceURL` ' +
          'pointing at her own collection endpoint (or a legitimate SP ' +
          'endpoint plus a `RelayState` she controls). She sends Alice ' +
          'the link. Alice authenticates at her IdP — which produces a ' +
          'real, signed Response and POSTs it to the URL Mallory ' +
          'specified. Without strict ACS-URL allowlisting at the IdP, ' +
          'this completes successfully and Mallory captures the Response.',
        impact:
          'Response delivery to attacker, plus secondary effects (session ' +
          'fixation, RelayState manipulation). Compounds with weak ' +
          'signature requirements on the request side.',
      },
    ],
    mitigations: [
      {
        action:
          'IdP MUST validate AssertionConsumerServiceURL against the SP\'s ' +
          'pre-registered metadata (exact match, no wildcards).',
        mitigates: ['authnrequest-forgery-session-fixation'],
      },
      {
        action:
          'For security-sensitive deployments, set ' +
          '`WantAuthnRequestsSigned=true` in IdP-side metadata so the IdP ' +
          'rejects unsigned AuthnRequests.',
        mitigates: ['authnrequest-forgery-session-fixation'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Core §3.4.1 (AuthnRequest)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.5 (Authentication Request Protocol)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  RelayState: {
    purpose:
      'Opaque value (max 80 bytes) carried alongside SAMLRequest / ' +
      'SAMLResponse to preserve SP application state across the SSO round ' +
      'trip. Common uses: original target URL the user wanted before being ' +
      'redirected to login, session correlation tokens, simple deep-link ' +
      'parameters.',
    attacks: [
      {
        id: 'relaystate-open-redirect',
        name: 'Open redirect via RelayState',
        scenario:
          'Without strict allowlisting, the convenience pattern of "after ' +
          'login, redirect the user to whatever URL is in RelayState" ' +
          'turns the SP\'s ACS endpoint into an open redirect on a ' +
          'trusted domain. Mallory crafts a SAML SSO link where ' +
          '`RelayState=https://mallory.example/credentials-page`. Alice ' +
          'clicks, authenticates via the IdP, comes back to the legitimate ' +
          'SP\'s ACS endpoint, and the SP\'s post-auth handler redirects ' +
          'her to Mallory\'s site. Mallory\'s site renders a perfect copy ' +
          'of the original SP\'s login page (the IdP authentication just ' +
          'happened, so the Referer chain looks normal). Real CVEs: ' +
          'Directus CVE-2026-22032, OpenCTI advisory, GitLab CVE-2023-1965 ' +
          '(and its bypass).',
        impact:
          'Phishing on a trusted-domain Referer chain that bypasses many ' +
          'anti-phishing heuristics. Bonus: an attacker who can write to ' +
          'RelayState can plant tracking pixels or cross-origin scripts ' +
          'on the post-auth page.',
      },
    ],
    mitigations: [
      {
        action:
          'Maintain an allowlist of permitted post-auth redirect targets ' +
          'and validate RelayState against it before issuing any 302.',
        mitigates: ['relaystate-open-redirect'],
      },
      {
        action:
          'If RelayState carries an arbitrary URL, it must originate from ' +
          'the SP itself (e.g. a signed value) — never from query ' +
          'parameters on the inbound flow.',
        mitigates: ['relaystate-open-redirect'],
      },
    ],
    references: [
      {
        label: 'CVE-2026-22032 (Directus RelayState open redirect)',
        href: 'https://www.miggo.io/vulnerability-database/cve/CVE-2026-22032',
      },
      {
        label: 'Snyk — Common SAML vulnerabilities',
        href: 'https://snyk.io/blog/common-saml-vulnerabilities-remediate/',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §7 (Profile-Specific Threats / Bindings)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  Signature: {
    purpose:
      'XML Digital Signature element wrapping cryptographic protection ' +
      'over the SAMLRequest, SAMLResponse, or Assertion. Built on XMLDSig ' +
      '— the most footgun-prone signature standard in widespread ' +
      'production use. XMLDSig\'s flexibility (signed subtree referenced ' +
      'by ID, multiple ID attributes, transforms, canonicalisations) is ' +
      'the source of nearly every SAML auth-bypass class.',
    attacks: [
      {
        id: 'xmldsig-comment-injection',
        name: 'Comment injection (Duo Security 2018)',
        scenario:
          '`<NameID>admin@victim<!--ignore-->.evil.com</NameID>` ' +
          'canonicalises differently than a naive parser reads it, so the ' +
          'signature covers one identity while the application sees ' +
          'another. In multiple widely-deployed SP implementations ' +
          '(OneLogin, Shibboleth, OmniAuth-SAML, etc.) the application ' +
          'read returns `admin@victim.com` while the signature still ' +
          'validates.',
        impact:
          'Cross-account impersonation against vulnerable SP libraries.',
      },
      {
        id: 'xmldsig-algorithm-downgrade',
        name: 'Algorithm downgrade',
        scenario:
          'Signature uses SHA-1 (long deprecated) or HMAC-SHA1 with a ' +
          'guessable key; attacker recomputes a valid signature on ' +
          'modified content.',
        impact:
          'Authentication bypass via cryptographic-strength downgrade.',
      },
      {
        id: 'xmldsig-keyinfo-trust',
        name: 'KeyInfo trust (cert from the message itself)',
        scenario:
          'Verifier extracts the signing cert from the Response\'s own ' +
          '`<KeyInfo>` element instead of comparing against the trusted ' +
          'IdP cert from metadata. Attacker embeds her own cert and the ' +
          'verifier validates the signature against it successfully.',
        impact:
          'Authentication bypass — the attacker chooses the signing key, ' +
          'so any signature she produces verifies.',
      },
      {
        id: 'xmldsig-reference-manipulation',
        name: 'Reference manipulation (multiple <Reference> elements)',
        scenario:
          'Multiple `<Reference>` elements where one signs the legitimate ' +
          'Assertion and another a malicious one; the verifier checks the ' +
          'first, the application reads the second.',
        impact:
          'Same shape as XSW: signature passes, application reads ' +
          'attacker-chosen content.',
      },
    ],
    mitigations: [
      {
        action:
          'Extract the trusted IdP signing certificate from pre-registered ' +
          'metadata, *never* from the Response\'s own KeyInfo.',
        mitigates: ['xmldsig-keyinfo-trust'],
      },
      {
        action:
          'Reject SHA-1 and other weak algorithms; require SHA-256 or ' +
          'stronger.',
        mitigates: ['xmldsig-algorithm-downgrade'],
      },
      {
        action:
          'Require exactly one Signature with one Reference covering the ' +
          'expected element.',
        mitigates: ['xmldsig-reference-manipulation'],
      },
      {
        action:
          'Operate only on the post-verification subtree — do not ' +
          're-traverse the DOM after verification.',
        mitigates: [
          'xmldsig-reference-manipulation',
          'xmldsig-comment-injection',
        ],
      },
      {
        action:
          'Fix `xml:id` ambiguities by using whitelisted ID attribute ' +
          'names only.',
        mitigates: ['xmldsig-reference-manipulation'],
      },
    ],
    references: [
      {
        label: 'PortSwigger — The Fragile Lock (2026 XSW research)',
        href: 'https://portswigger.net/research/the-fragile-lock',
      },
      {
        label: 'Duo Security — SAML Comment Injection (2018)',
        href: 'https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations',
      },
      {
        label: 'IBM — XML Signature Wrapping Explained',
        href: 'https://www.ibm.com/think/topics/xml-signature-wrapping',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.3 (Threats from XML)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  Issuer: {
    purpose:
      'EntityID of the party that issued the SAML message. On a Response, ' +
      'this is the IdP\'s Entity ID; on a Request, it is the SP\'s. Anchors ' +
      'the trust chain: SP looks up the Issuer in pre-registered metadata ' +
      'to find the public key for signature verification. The Issuer claim ' +
      'is unsigned bytes the verifier reads to *find the key that signs ' +
      'them* — a chicken-and-egg problem solved only by pre-registered ' +
      'trust.',
    attacks: [
      {
        id: 'golden-saml',
        name: 'Golden SAML',
        scenario:
          'Mallory gains administrative access to the IdP server (typically ' +
          'AD FS — but Entra ID and Okta have been hit in 2024-25 with ' +
          'variants known as "Silver SAML"). She extracts the IdP\'s ' +
          'private signing certificate. She now mints arbitrary Responses ' +
          'with any `Issuer`, `NameID`, `Conditions`, attribute set she ' +
          'wants — all with valid signatures from the legitimate IdP key. ' +
          'Used in the SUNBURST / SolarWinds intrusion chain to escalate ' +
          'from on-premises AD compromise to persistent cloud access. MFA ' +
          'is bypassed because the forged Response asserts the user was ' +
          'authenticated via "PasswordProtectedTransport" or any ' +
          'AuthnContextClassRef the attacker likes.',
        impact:
          'Persistent, MFA-bypassing access to every cloud service the IdP ' +
          'federates to (Microsoft 365, AWS, Salesforce, Workday, …).',
      },
    ],
    mitigations: [
      {
        action:
          'Hardware-protect the IdP signing key (HSM); restrict IdP ' +
          'server access aggressively; monitor cert export operations.',
        mitigates: ['golden-saml'],
      },
      {
        action:
          'Detection: correlate SP-side SAML logins against IdP-side ' +
          'authentication events. A SAML login at an SP without a ' +
          'corresponding authentication event at the IdP is a Golden SAML ' +
          'signal.',
        mitigates: ['golden-saml'],
      },
      {
        action:
          'Remediation: rotate the IdP signing certificate (which ' +
          'invalidates every active session and every forged token), then ' +
          'audit. Plan rotation drills before they\'re needed under ' +
          'incident pressure.',
        mitigates: ['golden-saml'],
      },
    ],
    references: [
      {
        label: 'CyberArk — Golden SAML Attack Technique (original disclosure)',
        href: 'https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps',
      },
      {
        label: 'Microsoft Entra — Understanding and Mitigating Golden SAML',
        href: 'https://techcommunity.microsoft.com/blog/microsoft-entra-blog/understanding-and-mitigating-golden-saml-attacks/4418864',
      },
      {
        label: 'Semperis — Silver SAML (Cloud variant of Golden SAML)',
        href: 'https://www.semperis.com/blog/meet-silver-saml/',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6 (Threat Model and Countermeasures)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  NameID: {
    purpose:
      'The user identifier carried in the Subject of an Assertion. Format ' +
      'depends on `NameIDFormat` — `persistent` (stable opaque ID per SP), ' +
      '`transient` (single-session pseudonym), `emailAddress`, ' +
      '`unspecified`. The SP\'s primary key for matching the SAML user to ' +
      'a local account.',
    attacks: [
      {
        id: 'nameid-comment-injection',
        name: 'Comment injection on NameID (Duo Security 2018)',
        scenario:
          'Mallory has a legitimate account `mallory@evil.com` at the same ' +
          'IdP that also authenticates `admin@victim.com`. She ' +
          'authenticates as herself, gets a real signed Response, then ' +
          'alters the Assertion in transit to set ' +
          '`<NameID>admin@victim.com<!---->.evil.com</NameID>`. The ' +
          'signature verifier canonicalises the XML (removing comments per ' +
          'C14N) and produces a hash that matches the original signature ' +
          '— OR fails to, depending on library and canonicalisation ' +
          'method. In multiple widely-deployed SP implementations ' +
          '(OneLogin, Shibboleth, OmniAuth-SAML) the application read ' +
          'returns `admin@victim.com` while the signature still validates.',
        impact:
          'Cross-account impersonation against vulnerable SP libraries.',
      },
      {
        id: 'nameid-mutable-identifier',
        name: 'Mutable identifier as account-matching key',
        scenario:
          'Using `emailAddress` NameIDFormat for account matching imports ' +
          'the cross-tenant impersonation problem into SAML — an attacker ' +
          'in a federated tenant assigns the victim\'s email to her own ' +
          'account; the SP, matching by email, links her sign-in to the ' +
          'victim\'s record.',
        impact:
          'Cross-tenant account takeover.',
      },
    ],
    mitigations: [
      {
        action:
          'Prefer `persistent` NameIDFormat over `emailAddress` for ' +
          'account-matching — opaque per-SP pseudonym, no cross-tenant ' +
          'collision.',
        mitigates: ['nameid-mutable-identifier'],
      },
      {
        action:
          'Match users by `(Issuer, NameID)` — never by attribute claims ' +
          'or by NameID alone across multiple IdPs.',
        mitigates: ['nameid-mutable-identifier'],
      },
      {
        action:
          'Use SAML libraries patched against the 2018 comment-injection ' +
          'class.',
        mitigates: ['nameid-comment-injection'],
      },
      {
        action:
          'Treat NameID as untrusted input until both signature ' +
          'verification and post-canonicalisation identifier extraction ' +
          'agree.',
        mitigates: ['nameid-comment-injection'],
      },
    ],
    references: [
      {
        label: 'Duo Security — Hacking SAML (Comment Injection)',
        href: 'https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations',
      },
      {
        label: 'SAML 2.0 Core §2.2 (NameIDType)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.4.1 (Stolen Assertion / Identifier issues)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  Conditions: {
    purpose:
      'XML element wrapping the assertion\'s validity constraints: ' +
      '`NotBefore`, `NotOnOrAfter` (temporal validity), ' +
      '`AudienceRestriction` (which SPs may consume the assertion), ' +
      '`OneTimeUse` (single-use marker). The verifier MUST evaluate every ' +
      'condition before trusting the assertion.',
    attacks: [
      {
        id: 'assertion-replay-validity-window',
        name: 'Assertion replay across the validity window',
        scenario:
          'Mallory captures a legitimate Response — perhaps from a ' +
          'non-TLS internal hop, a malicious browser extension, an ' +
          'HTTP-Redirect binding URL leaked to a server log. Without ' +
          'strict `NotOnOrAfter` enforcement (or with overly generous ' +
          'clock skew), she replays the same Response to the SP minutes ' +
          'or hours later. Without an assertion-ID replay cache, the SP ' +
          'accepts the same Assertion as a fresh login. Compounds with ' +
          'IdP-Initiated SSO where there is no `InResponseTo` to ' +
          'correlate against — replay defence is *only* the temporal ' +
          'window plus replay cache.',
        impact:
          'Authentication via captured-Response replay.',
      },
    ],
    mitigations: [
      {
        action:
          'Reject Responses with `NotOnOrAfter` in the past; allow only ' +
          'small clock-skew tolerance (~5 minutes max).',
        mitigates: ['assertion-replay-validity-window'],
      },
      {
        action:
          'Cache Assertion `ID` values for the duration of the validity ' +
          'window and reject duplicates.',
        mitigates: ['assertion-replay-validity-window'],
      },
      {
        action:
          'Require short validity windows (~5 minutes) — long windows are ' +
          'unsafe regardless of caching.',
        mitigates: ['assertion-replay-validity-window'],
      },
      {
        action:
          'For IdP-Initiated SSO, treat the replay-ID cache as mandatory ' +
          'because there is no `InResponseTo` cross-check.',
        mitigates: ['assertion-replay-validity-window'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Core §2.5 (Conditions)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.4.2 (Stolen Assertion / Replay)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  AudienceRestriction: {
    purpose:
      'A child of `Conditions` listing one or more `<Audience>` URIs. The ' +
      'Assertion is valid *only* when consumed by an SP whose EntityID ' +
      'appears in the list. SAML\'s equivalent of the JWT `aud` claim — ' +
      'same concept, same mitigation responsibilities on the receiving ' +
      'side.',
    attacks: [
      {
        id: 'cross-sp-assertion-forwarding',
        name: 'Cross-SP assertion forwarding',
        scenario:
          'Mallory operates SP A (a low-privilege "free utility" service) ' +
          'in the same federation as the high-value SP B. Alice signs into ' +
          'A. Mallory captures the Assertion the IdP issued for A (it ' +
          'arrived at her own server in plaintext form post-decryption). ' +
          'Mallory replays the Assertion to SP B. SP B verifies the IdP ' +
          'signature (valid), the temporal window (valid), but skips the ' +
          'Audience check — and authenticates Alice. Mallory now has a ' +
          'session at SP B as Alice without compromising the IdP, MFA, or ' +
          'Alice\'s credentials.',
        impact:
          'Cross-SP identity bleed in shared-IdP federations.',
      },
    ],
    mitigations: [
      {
        action:
          'Every SP MUST verify its own EntityID appears in ' +
          '`<AudienceRestriction>` before trusting the Assertion.',
        mitigates: ['cross-sp-assertion-forwarding'],
      },
      {
        action:
          'IdP MUST set `<AudienceRestriction>` to the specific requesting ' +
          'SP — never a wildcard or shared placeholder.',
        mitigates: ['cross-sp-assertion-forwarding'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Core §2.5.1.4 (AudienceRestriction)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.4.4 (Forwarded / Misdirected Assertion)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  SubjectConfirmation: {
    purpose:
      'Element on the Assertion\'s Subject specifying *how* the SP can ' +
      'confirm the Assertion is being presented by the right party. For ' +
      'SP-Initiated SSO via HTTP-POST (the common case), method is ' +
      '`bearer` and the `<SubjectConfirmationData>` carries `Recipient` ' +
      '(target ACS URL), `NotOnOrAfter` (delivery deadline), and ' +
      '`InResponseTo` (the original AuthnRequest ID).',
    attacks: [
      {
        id: 'unsolicited-response-injection',
        name: 'Unsolicited Response injection',
        scenario:
          'The SP\'s ACS endpoint accepts any well-formed POST. Mallory ' +
          'captures a legitimate Response (or generates one with a ' +
          'different InResponseTo) and injects it into Alice\'s browser ' +
          'session at the target SP. Without `InResponseTo` validation, ' +
          'the SP accepts the Response as if it had requested it. Variant: ' +
          'replay across SPs by skipping `Recipient` validation.',
        impact:
          'Authentication bypass via cross-flow Response injection. ' +
          'IdP-Initiated SSO is structurally exposed to this class — it ' +
          'has no `InResponseTo` to validate against (the SP never sent a ' +
          'request), so the only replay defence is the assertion-ID cache.',
      },
    ],
    mitigations: [
      {
        action:
          'SP-Initiated SSO MUST validate `InResponseTo` against the ' +
          'AuthnRequest ID stored in the user\'s session at request time. ' +
          'Reject if mismatch or missing.',
        mitigates: ['unsolicited-response-injection'],
      },
      {
        action:
          'SP MUST validate `Recipient` matches this SP\'s ACS URL exactly.',
        mitigates: ['unsolicited-response-injection'],
      },
      {
        action:
          'Consider disabling IdP-Initiated SSO entirely if the security ' +
          'trade-off does not justify the convenience.',
        mitigates: ['unsolicited-response-injection'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Core §2.4 (Subject Confirmation)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Profiles §4.1.4.5 (POST Binding Validation)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.4.2 / §6.4.4 (Replay / Forwarded Assertion)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  AssertionConsumerServiceURL: {
    purpose:
      'The URL at which the SP receives SAML Responses. Sent on the ' +
      'AuthnRequest by the SP and pre-registered in the SP\'s metadata. ' +
      'The IdP MUST validate it matches a registered ACS URL before ' +
      'sending the Response. SAML\'s analogue of OAuth\'s `redirect_uri` ' +
      '— the same exact-match story, same attack class when matching is ' +
      'loose.',
    attacks: [
      {
        id: 'response-redirection-via-acs',
        name: 'Response redirection via loose ACS matching',
        scenario:
          'If the IdP doesn\'t strictly validate ' +
          'AssertionConsumerServiceURL against pre-registered SP metadata, ' +
          'the SP\'s authenticated Responses can be redirected to attacker ' +
          'endpoints. Mallory crafts an AuthnRequest using the legitimate ' +
          'SP\'s Issuer but `AssertionConsumerServiceURL` pointing at her ' +
          'own server (`https://victim-sp.example.com.evil.com/acs`, or ' +
          'exploiting wildcard/prefix matching in the IdP\'s allowlist). ' +
          'Alice clicks the link, authenticates at the IdP, the IdP signs ' +
          'a Response and POSTs it to Mallory\'s endpoint. Mallory now ' +
          'has a fully-signed valid Response for Alice, which she can ' +
          'replay (within the validity window) to the legitimate SP.',
        impact:
          'Response delivery to attacker, leading to assertion replay ' +
          'against the legitimate SP.',
      },
    ],
    mitigations: [
      {
        action:
          'IdP MUST require exact-match against pre-registered ACS URLs ' +
          'in SP metadata — no prefix matching, no wildcards, no derived ' +
          'URLs.',
        mitigates: ['response-redirection-via-acs'],
      },
      {
        action:
          'SP metadata SHOULD register ACS URLs narrowly — one per ' +
          'binding, not a wildcard pattern.',
        mitigates: ['response-redirection-via-acs'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Profiles §4.1.4.1 (AssertionConsumerServiceURL)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.1.2 (Threats to System / endpoint binding)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  entityID: {
    purpose:
      'A globally unique identifier (typically a URL) for an SP or IdP in ' +
      'a SAML federation. Anchors all metadata — the IdP looks up the SP\'s ' +
      '`entityID` in its trust store to find ACS URLs, supported ' +
      'NameIDFormats, signing certs, and so on.',
    attacks: [
      {
        id: 'metadata-onboarding-mitm',
        name: 'Federation-onboarding metadata MITM',
        scenario:
          'The SP and IdP team are setting up a new federation. They ' +
          'exchange metadata URLs over email. Mallory, who has compromised ' +
          'the network path or the email channel, substitutes her own ' +
          'metadata at the URL the IdP fetches — including her own ' +
          'signing certificate. The IdP, trusting the metadata fetched at ' +
          'federation-setup time, now treats Mallory\'s cert as the SP\'s. ' +
          'Mallory can then forge SP-side requests at will (less impactful ' +
          'than Golden SAML, but a foothold).',
        impact:
          'Federation trust subversion at onboarding.',
      },
      {
        id: 'metadata-xxe',
        name: 'XXE during metadata XML processing',
        scenario:
          'SP-provided metadata XML processed by the IdP with DTDs ' +
          'enabled is a parser-side vulnerability surface before any ' +
          'signature is verified. CVE-2024-52806 (simplesamlphp/saml2), ' +
          'CVE-2017-1000452 (samlify), and others demonstrate the class. ' +
          'A malicious metadata document at parse time can read files / ' +
          'cause SSRF before signature checks run.',
        impact:
          'File disclosure / SSRF / DoS at metadata-load time.',
      },
    ],
    mitigations: [
      {
        action:
          'Fetch metadata over HTTPS with strict certificate validation.',
        mitigates: ['metadata-onboarding-mitm'],
      },
      {
        action:
          'Verify metadata XML signatures — metadata can itself be signed ' +
          'and SHOULD be in production federations.',
        mitigates: ['metadata-onboarding-mitm'],
      },
      {
        action:
          'Disable DTD / external-entity processing in the XML parser.',
        mitigates: ['metadata-xxe'],
      },
      {
        action:
          'For high-assurance federations (eduGAIN, government), use a ' +
          'federation metadata aggregator that signs the entire metadata ' +
          'bundle.',
        mitigates: ['metadata-onboarding-mitm'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Metadata §2.3 (entityID)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
      },
      {
        label: 'CVE-2024-52806 (simplesamlphp/saml2 XXE)',
        href: 'https://security.snyk.io/vuln/SNYK-PHP-SIMPLESAMLPHPSAML2-8449140',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.5 (Trust Establishment / Metadata)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  WantAssertionsSigned: {
    purpose:
      'Boolean attribute on the SP\'s `<SPSSODescriptor>` in metadata ' +
      'declaring whether the SP requires the IdP to sign Assertions (in ' +
      'addition to or instead of signing the enclosing Response). The ' +
      'single biggest configuration trap in SAML deployments: ' +
      '`WantAssertionsSigned=false` (often the default) means the SP ' +
      'accepts an unsigned Assertion as long as the enclosing Response is ' +
      'signed.',
    attacks: [
      {
        id: 'response-only-signing-xsw',
        name: 'XSW exploiting Response-only signing',
        scenario:
          'The IdP signs only the `<Response>` element, not the inner ' +
          '`<Assertion>`. Mallory intercepts a legitimate Response and ' +
          'replaces the Assertion with one she crafted (her chosen NameID, ' +
          'her chosen attributes). The Response\'s signature still ' +
          'references the Response element — which the verifier validates ' +
          'successfully — but the Assertion inside is now Mallory\'s. ' +
          'Application logic reads the swapped Assertion and authenticates ' +
          'her as anyone she wants. This is the low-effort XSW variant — ' +
          'no clever DOM manipulation needed, just "signing the wrong ' +
          'element".',
        impact:
          'Configuration-driven authentication bypass.',
      },
    ],
    mitigations: [
      {
        action:
          'Every SP metadata MUST declare `WantAssertionsSigned=true`.',
        mitigates: ['response-only-signing-xsw'],
      },
      {
        action:
          'Every IdP producing Responses for production SPs MUST sign the ' +
          'Assertion (in addition to or instead of the Response).',
        mitigates: ['response-only-signing-xsw'],
      },
      {
        action:
          'Auditing tip: parse every SP\'s `SPSSODescriptor` in your ' +
          'federation and flag any with `WantAssertionsSigned=false` or ' +
          'missing.',
        mitigates: ['response-only-signing-xsw'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Metadata §2.4.2 (WantAssertionsSigned)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
      },
      {
        label: 'WorkOS — Fun with SAML SSO Footguns',
        href: 'https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.3 (XML Signature requirements)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },

  NameIDPolicy: {
    purpose:
      'On the AuthnRequest, the SP\'s preference for which NameIDFormat ' +
      'the IdP should use in the resulting Assertion. Common values: ' +
      '`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (stable ' +
      'pseudonym per SP), `transient` (single-session pseudonym), ' +
      '`emailAddress`, `unspecified`.',
    attacks: [
      {
        id: 'nameidpolicy-cross-tenant-confusion',
        name: 'Cross-tenant identifier confusion',
        scenario:
          'Choosing `emailAddress` or `unspecified` as the account-' +
          'matching identifier opens cross-tenant impersonation: in ' +
          'multi-tenant IdPs (Entra ID, multi-domain ADFS) where users ' +
          'in different tenants can share email values, an attacker-' +
          'controlled tenant can mint Assertions claiming any email ' +
          'address — and SPs matching by email link the attacker into ' +
          'the legitimate user\'s account. Mallory operates her own tenant ' +
          'in a multi-tenant IdP federated with the target SP. She creates ' +
          'a user in her tenant with email `alice@victim-corp.com`. She ' +
          'authenticates and the IdP issues a signed Assertion with that ' +
          'email as NameID. The SP, matching users by email, links ' +
          'Mallory\'s sign-in to Alice\'s legitimate account. Cryptography ' +
          'is fine; the failure is in trusting a mutable identifier as a ' +
          'primary key. The same pattern in OIDC is known as the nOAuth ' +
          'attack (Descope, 2023); the SAML version has the same shape.',
        impact:
          'Cross-tenant account takeover.',
      },
    ],
    mitigations: [
      {
        action:
          'SP MUST request and match by `persistent` NameIDFormat — the ' +
          'IdP issues a stable opaque pseudonym unique to (this user, ' +
          'this SP), with no cross-tenant collision.',
        mitigates: ['nameidpolicy-cross-tenant-confusion'],
      },
      {
        action:
          'Use `(Issuer, NameID)` as the composite primary key. ' +
          '`transient` is for stateless single-session use; `emailAddress` ' +
          'is for non-security-critical applications.',
        mitigates: ['nameidpolicy-cross-tenant-confusion'],
      },
    ],
    references: [
      {
        label: 'SAML 2.0 Core §3.4.1.1 (NameIDPolicy)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'Descope nOAuth disclosure (same pattern, OIDC context)',
        href: 'https://www.descope.com/blog/post/noauth',
      },
      {
        label: 'SAML 2.0 Security and Privacy Considerations §6.4.1 (Identifier-related issues)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf',
      },
    ],
  },
}
