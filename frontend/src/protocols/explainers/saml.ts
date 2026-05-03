/**
 * SAML 2.0 — Parameter Explainers
 *
 * XML-based SSO. Parameter names use PascalCase per the SAML wire
 * format (`SAMLResponse`, `RelayState`, `NameID`, etc.). Attack surface
 * is fundamentally different from JSON-based protocols: XML Signature
 * Wrapping (XSW), Golden SAML, XXE, comment injection, signature
 * stripping all live here.
 */

import type { ParameterExplainer } from './index'

export const SAML_EXPLAINERS: Record<string, ParameterExplainer> = {
  SAMLResponse: {
    purpose:
      'Base64-encoded XML SAML Response containing one or more Assertions ' +
      'about the authenticated user. Posted by the IdP to the SP\'s ' +
      'Assertion Consumer Service URL after successful authentication. ' +
      'The cryptographic deliverable of the entire SP-Initiated SSO flow.',
    withoutIt:
      'The risk is in *how the SP parses and validates* the Response, not ' +
      'in receiving it. SAML\'s XML model is large enough that the ' +
      'parser and the signature verifier can disagree about which bytes ' +
      'matter — and every disagreement is a potential auth bypass.',
    attack:
      'XML Signature Wrapping (XSW). The IdP signs a Response containing ' +
      'a legitimate Assertion. Mallory intercepts it, embeds a *second* ' +
      'malicious Assertion (with her chosen NameID, attributes, audience) ' +
      'into the same XML document at a different location, and forwards ' +
      'it to the SP. The signature verifier follows ID/URI references and ' +
      'validates the legitimate Assertion — signature checks pass. The SP\'s ' +
      'business logic, however, walks the DOM and consumes the *first* ' +
      'Assertion it finds (Mallory\'s). Auth bypass with no broken ' +
      'cryptography. Multiple 2024 high-severity CVEs: Ruby-SAML ' +
      'CVE-2024-45409 (CVSS 9.8, full impersonation, GitLab impacted); ' +
      'GitHub Enterprise Server CVE-2024-6800; HaloITSM CVE-2024-6202. ' +
      'Companion attacks: signature stripping (remove the Signature ' +
      'element entirely and the verifier returns "no signature to ' +
      'check" instead of failing), XXE (DTDs enabled by default in many ' +
      'XML parsers — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` reads ' +
      'arbitrary files; CVE-2024-52806 in simplesamlphp), and comment ' +
      'injection (`<NameID>admin@victim.com<!--x-->@evil.com</NameID>` — ' +
      'signature canonicalisation and application parser disagree on ' +
      'where the value ends).',
    impact:
      'Authentication bypass with full identity impersonation. Defences: ' +
      '(1) verify signature *first*, then operate only on the verified ' +
      'subtree — do not re-traverse the DOM; (2) reject Responses ' +
      'containing more than one Assertion or unexpected sibling nodes; ' +
      '(3) disable DTD processing in your XML parser; (4) use a battle-' +
      'tested library and keep it patched (XSW research is still ' +
      'discovering new bypasses against widely-deployed libraries — ' +
      'PortSwigger\'s 2026 "Fragile Lock" research broke several).',
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
    ],
  },

  SAMLRequest: {
    purpose:
      'Base64-encoded (and DEFLATE-compressed for HTTP-Redirect binding) ' +
      'XML AuthnRequest or LogoutRequest the SP sends to the IdP. ' +
      'Specifies the SP\'s identity (Issuer), where to deliver the ' +
      'response (AssertionConsumerServiceURL), session controls ' +
      '(ForceAuthn, IsPassive), and NameID format preferences.',
    withoutIt:
      'A SAML deployment that does not require signed AuthnRequests ' +
      '(`AuthnRequestsSigned=false` in IdP-side metadata about the SP) ' +
      'accepts any request claiming to be from the SP. An attacker can ' +
      'forge requests — different impact than forging Responses, but ' +
      'still useful for nuisance, session fixation, or as part of a chain.',
    attack:
      'AuthnRequest forgery for session fixation. Mallory crafts an ' +
      'AuthnRequest with `AssertionConsumerServiceURL` pointing at her ' +
      'own collection endpoint (or a legitimate SP endpoint plus a ' +
      '`RelayState` she controls). She sends Alice the link. Alice ' +
      'authenticates at her IdP — which produces a real, signed Response ' +
      'and POSTs it to the URL Mallory specified. Without strict ACS-URL ' +
      'allowlisting at the IdP (matched against the SP\'s registered ' +
      'metadata), this completes successfully and Mallory captures the ' +
      'Response. Compounds with weak signature requirements on the ' +
      'request side.',
    impact:
      'Response delivery to attacker, plus secondary effects (session ' +
      'fixation, RelayState manipulation). Defence: IdP MUST validate ' +
      'AssertionConsumerServiceURL against the SP\'s pre-registered ' +
      'metadata; SHOULD require signed AuthnRequests for security-' +
      'sensitive deployments (set `WantAuthnRequestsSigned=true`).',
    references: [
      {
        label: 'SAML 2.0 Core §3.4.1 (AuthnRequest)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
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
    withoutIt:
      'The risk is the convenience pattern of "after login, redirect the ' +
      'user to whatever URL is in RelayState". Without strict allowlisting ' +
      'this turns the SP\'s ACS endpoint into an open redirect on a ' +
      'trusted domain.',
    attack:
      'Open redirect via RelayState. Mallory crafts a SAML SSO link where ' +
      '`RelayState=https://mallory.example/credentials-page`. Alice clicks, ' +
      'authenticates via the IdP, comes back to the legitimate SP\'s ACS ' +
      'endpoint, and the SP\'s post-auth handler redirects her to ' +
      'Mallory\'s site. Mallory\'s site renders a perfect copy of the ' +
      'original SP\'s login page (the IdP authentication just happened, ' +
      'so the Referer chain looks normal). Real CVEs: Directus ' +
      'CVE-2026-22032, OpenCTI advisory, GitLab CVE-2023-1965 (and its ' +
      'bypass). Bonus: an attacker who can write to RelayState can also ' +
      'plant tracking pixels or cross-origin scripts on the post-auth ' +
      'page.',
    impact:
      'Phishing on a trusted-domain Referer chain that bypasses many ' +
      'anti-phishing heuristics. Defence: maintain an allowlist of ' +
      'permitted post-auth redirect targets and validate RelayState ' +
      'against it before issuing any 302. If RelayState carries an ' +
      'arbitrary URL, it must originate from the SP itself (e.g. a ' +
      'signed value) — never from query parameters on the inbound flow.',
    references: [
      {
        label: 'CVE-2026-22032 (Directus RelayState open redirect)',
        href: 'https://www.miggo.io/vulnerability-database/cve/CVE-2026-22032',
      },
      {
        label: 'Snyk — Common SAML vulnerabilities',
        href: 'https://snyk.io/blog/common-saml-vulnerabilities-remediate/',
      },
    ],
  },

  Signature: {
    purpose:
      'XML Digital Signature element wrapping cryptographic protection ' +
      'over the SAMLRequest, SAMLResponse, or Assertion. Built on ' +
      'XMLDSig — the most footgun-prone signature standard in widespread ' +
      'production use.',
    withoutIt:
      'Without signature verification: every Assertion is forgeable. With ' +
      'signature verification *but done wrong*: the protocol *appears* to ' +
      'work but the signature\'s cryptographic guarantee does not transfer ' +
      'to the bytes the application logic actually consumes. XMLDSig\'s ' +
      'flexibility (signed subtree referenced by ID, multiple ID ' +
      'attributes, transforms, canonicalisations) is the source of nearly ' +
      'every SAML auth-bypass class.',
    attack:
      'XML Signature Wrapping (XSW) is the marquee attack — see ' +
      '`SAMLResponse` for the full walk-through. Other XMLDSig-specific ' +
      'attacks: (1) **Comment injection** (Duo Security 2018) — ' +
      '`<NameID>admin@victim<!--ignore-->.evil.com</NameID>` ' +
      'canonicalises differently than a naive parser reads it, so the ' +
      'signature covers one identity while the application sees another. ' +
      '(2) **Algorithm downgrade** — signature uses SHA-1 (long deprecated) ' +
      'or HMAC-SHA1 with a guessable key; attacker recomputes a valid ' +
      'signature. (3) **KeyInfo trust** — verifier extracts the signing ' +
      'cert from the Response\'s own `<KeyInfo>` element instead of ' +
      'comparing against the trusted IdP cert from metadata; attacker ' +
      'embeds her own cert and the verifier validates against it ' +
      'successfully. (4) **Reference manipulation** — multiple ' +
      '`<Reference>` elements where one signs the legitimate Assertion ' +
      'and another a malicious one; verifier checks the first, ' +
      'application reads the second.',
    impact:
      'Signature verification done wrong = no signature verification. ' +
      'Defences: (1) extract the trusted IdP signing certificate from ' +
      'pre-registered metadata, *never* from the Response\'s own KeyInfo; ' +
      '(2) reject SHA-1 and other weak algorithms; (3) require exactly ' +
      'one Signature with one Reference covering the expected element; ' +
      '(4) operate only on the post-verification subtree — do not re-' +
      'traverse the DOM after verification; (5) fix `xml:id` ambiguities ' +
      'by using whitelisted ID attribute names only.',
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
    ],
  },

  Issuer: {
    purpose:
      'EntityID of the party that issued the SAML message. On a Response, ' +
      'this is the IdP\'s Entity ID; on a Request, it is the SP\'s. ' +
      'Anchors the trust chain: SP looks up the Issuer in pre-registered ' +
      'metadata to find the public key for signature verification.',
    withoutIt:
      'If the SP looks up trust by something *other* than Issuer (or ' +
      'derives the trust key from the Response itself rather than from ' +
      'metadata), the entire chain collapses. The Issuer claim is the ' +
      'protocol-level statement of "this came from this IdP" — and it is ' +
      'unsigned bytes the verifier reads to *find the key that signs ' +
      'them*, a chicken-and-egg problem solved only by pre-registered ' +
      'trust.',
    attack:
      'Golden SAML. Mallory gains administrative access to the IdP server ' +
      '(typically AD FS — but Entra ID and Okta have been hit in 2024-25 ' +
      'with variants known as "Silver SAML"). She extracts the IdP\'s ' +
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
      'federates to (Microsoft 365, AWS, Salesforce, Workday, …). ' +
      'Detection requires correlating SP-side SAML logins against IdP-side ' +
      'authentication events: a SAML login at an SP without a corresponding ' +
      'authentication event at the IdP is a Golden SAML signal. ' +
      'Remediation: rotate the IdP signing certificate (which invalidates ' +
      'every active session and every forged token), then audit. ' +
      'Prevention: hardware-protect the IdP signing key (HSM), restrict ' +
      'IdP server access aggressively, monitor cert export operations.',
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
    ],
  },

  NameID: {
    purpose:
      'The user identifier carried in the Subject of an Assertion. Format ' +
      'depends on `NameIDFormat` — `persistent` (stable opaque ID per SP), ' +
      '`transient` (single-session pseudonym), `emailAddress`, ' +
      '`unspecified`. The SP\'s primary key for matching the SAML user to ' +
      'a local account.',
    withoutIt:
      'Two failure modes: (1) **Mutable identifier** — using ' +
      '`emailAddress` NameIDFormat for account matching imports the ' +
      'OIDC nOAuth attack class into SAML (cross-tenant impersonation ' +
      'via attacker-controlled email values); (2) **Comment injection** ' +
      '— XML parser quirks where signature canonicalisation and ' +
      'application read disagree on the identifier value.',
    attack:
      'Comment injection on NameID (Duo Security, 2018). Mallory has a ' +
      'legitimate account `mallory@evil.com` at the same IdP that also ' +
      'authenticates `admin@victim.com`. She authenticates as herself, ' +
      'gets a real signed Response, then alters the Assertion in transit ' +
      'to set `<NameID>admin@victim.com<!---->.evil.com</NameID>`. The ' +
      'signature verifier canonicalises the XML (removing comments per ' +
      'C14N) and produces a hash that matches the original signature — ' +
      'OR fails to, depending on library and canonicalisation method. ' +
      'In multiple widely-deployed SP implementations (OneLogin, Shibboleth, ' +
      'OmniAuth-SAML, etc.) the application read returns ' +
      '`admin@victim.com` while the signature still validates. Result: ' +
      'authenticated as the wrong user.',
    impact:
      'Cross-account impersonation against vulnerable SP libraries. ' +
      'Defences: (1) prefer `persistent` NameIDFormat over `emailAddress` ' +
      'for account-matching; (2) match users by `(Issuer, NameID)` — ' +
      'never by attribute claims; (3) use SAML libraries patched against ' +
      'the 2018 comment-injection class; (4) treat NameID as untrusted ' +
      'input until both signature verification and post-canonicalisation ' +
      'identifier extraction agree.',
    references: [
      {
        label: 'Duo Security — Hacking SAML (Comment Injection)',
        href: 'https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations',
      },
      {
        label: 'SAML 2.0 Core §2.2 (NameIDType)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
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
    withoutIt:
      'Skipping any condition opens a corresponding attack: skip ' +
      '`NotOnOrAfter` and stale assertions become reusable indefinitely; ' +
      'skip `AudienceRestriction` and assertions for one SP work at ' +
      'another; skip `OneTimeUse` and replay attacks succeed silently.',
    attack:
      'Assertion replay across the validity window. Mallory captures a ' +
      'legitimate Response — perhaps from a non-TLS internal hop, a ' +
      'malicious browser extension, an HTTP-Redirect binding URL leaked ' +
      'to a server log. Without strict `NotOnOrAfter` enforcement (or with ' +
      'overly generous clock skew), she replays the same Response to the ' +
      'SP minutes or hours later. Without an assertion-ID replay cache, ' +
      'the SP accepts the same Assertion as a fresh login. Compounds with ' +
      'the IdP-Initiated SSO flow where there is no `InResponseTo` to ' +
      'correlate against — replay defence is *only* the temporal window ' +
      'plus replay cache.',
    impact:
      'Authentication via captured-Response replay. Defences: (1) ' +
      'reject Responses with `NotOnOrAfter` in the past (small clock-skew ' +
      'tolerance, ~5 minutes max); (2) cache Assertion `ID` values for the ' +
      'duration of the validity window and reject duplicates; (3) require ' +
      'short validity windows (~5 minutes) — long windows are unsafe ' +
      'regardless of caching; (4) for IdP-Initiated SSO, treat replay-' +
      'cache as mandatory because there is no `InResponseTo` cross-check.',
    references: [
      {
        label: 'SAML 2.0 Core §2.5 (Conditions)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
    ],
  },

  AudienceRestriction: {
    purpose:
      'A child of `Conditions` listing one or more `<Audience>` URIs. ' +
      'The Assertion is valid *only* when consumed by an SP whose ' +
      'EntityID appears in the list. SAML\'s equivalent of the JWT ' +
      '`aud` claim — same concept, same mitigation responsibilities ' +
      'on the receiving side.',
    withoutIt:
      'If the SP skips the Audience check, every Assertion the IdP ever ' +
      'issued for any SP works at this SP. In a federation with shared ' +
      'IdP across many tenants or apps, that means a malicious app ' +
      'operator (or a compromised co-tenant) can replay assertions ' +
      'collected from their own users at the target SP.',
    attack:
      'Cross-SP assertion forwarding. Mallory operates SP A (a low-' +
      'privilege "free utility" service) in the same federation as the ' +
      'high-value SP B. Alice signs into A. Mallory captures the ' +
      'Assertion the IdP issued for A (it arrived at her own server in ' +
      'plaintext form post-decryption). Mallory replays the Assertion to ' +
      'SP B. SP B verifies the IdP signature (valid), the temporal ' +
      'window (valid), but skips Audience check — and authenticates ' +
      'Alice. Mallory now has a session at SP B as Alice without ' +
      'compromising the IdP, MFA, or Alice\'s credentials.',
    impact:
      'Cross-SP identity bleed in shared-IdP federations. Defence: every ' +
      'SP MUST verify its own EntityID appears in `<AudienceRestriction>`. ' +
      'IdP MUST set `<AudienceRestriction>` to the specific requesting SP, ' +
      'never a wildcard or a shared placeholder. Same risk profile and ' +
      'mitigation as JWT `aud` validation.',
    references: [
      {
        label: 'SAML 2.0 Core §2.5.1.4 (AudienceRestriction)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
    ],
  },

  SubjectConfirmation: {
    purpose:
      'Element on the Assertion\'s Subject specifying *how* the SP can ' +
      'confirm the Assertion is being presented by the right party. ' +
      'For SP-Initiated SSO via HTTP-POST (the common case), method is ' +
      '`bearer` and the `<SubjectConfirmationData>` carries `Recipient` ' +
      '(target ACS URL), `NotOnOrAfter` (delivery deadline), and ' +
      '`InResponseTo` (the original AuthnRequest ID).',
    withoutIt:
      'Two specific checks lift here: `InResponseTo` ties the Response ' +
      'to a request *this* SP started (defence against unsolicited ' +
      'response injection in SP-Initiated SSO); `Recipient` ties the ' +
      'Response to *this* SP\'s ACS URL (defence against cross-SP ' +
      'forwarding).',
    attack:
      'Unsolicited Response injection into SP-Initiated SSO. The SP\'s ' +
      'ACS endpoint accepts any well-formed POST. Mallory captures a ' +
      'legitimate Response (or generates one with a different ' +
      'InResponseTo) and injects it into Alice\'s browser session at ' +
      'the target SP. Without `InResponseTo` validation, the SP accepts ' +
      'the Response as if it had requested it. Variant: replay across ' +
      'SPs by skipping `Recipient` validation. ' +
      'IdP-Initiated SSO is structurally exposed to this class — it has ' +
      'no `InResponseTo` to validate against (the SP never sent a ' +
      'request), so the only replay defence is the assertion-ID cache.',
    impact:
      'Authentication bypass via cross-flow Response injection. ' +
      'Defences: SP-Initiated SSO MUST validate `InResponseTo` against ' +
      'the AuthnRequest ID stored in the user\'s session at request time ' +
      '(reject if mismatch or missing). MUST validate `Recipient` ' +
      'matches this SP\'s ACS URL exactly. For IdP-Initiated SSO, ' +
      'consider whether the security trade-off justifies the convenience — ' +
      'many SPs disable IdP-Initiated entirely.',
    references: [
      {
        label: 'SAML 2.0 Core §2.4 (Subject Confirmation)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'SAML 2.0 Profiles §4.1.4.5 (POST Binding Validation)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
      },
    ],
  },

  AssertionConsumerServiceURL: {
    purpose:
      'The URL at which the SP receives SAML Responses. Sent on the ' +
      'AuthnRequest by the SP and pre-registered in the SP\'s metadata. ' +
      'The IdP MUST validate it matches a registered ACS URL before ' +
      'sending the Response. SAML\'s analogue of OAuth\'s `redirect_uri` ' +
      '— the same exact-match story, same attack class when matching ' +
      'is loose.',
    withoutIt:
      'If the IdP doesn\'t strictly validate AssertionConsumerServiceURL ' +
      'against pre-registered SP metadata, the SP\'s authenticated ' +
      'Responses can be redirected to attacker endpoints — exactly the ' +
      'OAuth redirect_uri loose-matching attack class.',
    attack:
      'Response redirection attack. Mallory crafts an AuthnRequest using ' +
      'the legitimate SP\'s Issuer but `AssertionConsumerServiceURL` ' +
      'pointing at her own server (`https://victim-sp.example.com.evil.' +
      'com/acs`, or exploiting wildcard/prefix matching in the IdP\'s ' +
      'allowlist). Alice clicks the link, authenticates at the IdP, the ' +
      'IdP signs a Response and POSTs it to Mallory\'s endpoint. Mallory ' +
      'now has a fully-signed valid Response for Alice, which she can ' +
      'replay (within the validity window) to the legitimate SP.',
    impact:
      'Response delivery to attacker, leading to assertion replay against ' +
      'the legitimate SP. Defence: IdP MUST require exact-match against ' +
      'pre-registered ACS URLs in SP metadata — no prefix matching, no ' +
      'wildcards, no derived URLs. SP metadata SHOULD register ACS URLs ' +
      'narrowly (one per binding, not a wildcard pattern).',
    references: [
      {
        label: 'SAML 2.0 Profiles §4.1.4.1 (AssertionConsumerServiceURL)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
      },
    ],
  },

  entityID: {
    purpose:
      'A globally unique identifier (typically a URL) for an SP or IdP ' +
      'in a SAML federation. Anchors all metadata — the IdP looks up the ' +
      'SP\'s `entityID` in its trust store to find ACS URLs, supported ' +
      'NameIDFormats, signing certs, and so on.',
    withoutIt:
      'Two failure modes around the metadata document itself, not the ' +
      'entityID per se: (1) **Metadata MITM** — fetching SP/IdP metadata ' +
      'over HTTP (or HTTPS without certificate pinning) lets an attacker ' +
      'substitute the trust anchors during initial federation setup; ' +
      '(2) **Metadata XXE** — SP-provided metadata XML processed by the ' +
      'IdP with DTDs enabled is a parser-side vulnerability surface ' +
      'before any signature is verified.',
    attack:
      'Federation-onboarding MITM. The SP and IdP team are setting up a ' +
      'new federation. They exchange metadata URLs over email. Mallory, ' +
      'who has compromised the network path or the email channel, ' +
      'substitutes her own metadata at the URL the IdP fetches — ' +
      'including her own signing certificate. The IdP, trusting the ' +
      'metadata fetched at federation-setup time, now treats Mallory\'s ' +
      'cert as the SP\'s. Mallory can then forge SP-side requests at ' +
      'will (less impactful than Golden SAML, but a foothold). Combined ' +
      'with XXE in metadata XML processing (CVE-2024-52806, ' +
      'CVE-2017-1000452, others), a malicious metadata document at ' +
      'parse time can read files / SSRF before signature checks even run.',
    impact:
      'Federation trust subversion at onboarding. Defences: (1) fetch ' +
      'metadata over HTTPS with strict certificate validation; (2) ' +
      'verify metadata XML signatures (yes, metadata can itself be ' +
      'signed and SHOULD be in production federations); (3) disable ' +
      'DTD/external-entity processing in the XML parser; (4) for ' +
      'high-assurance federations (eduGAIN, government), use a federation ' +
      'metadata aggregator that signs the entire metadata bundle.',
    references: [
      {
        label: 'SAML 2.0 Metadata §2.3 (entityID)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
      },
      {
        label: 'CVE-2024-52806 (simplesamlphp/saml2 XXE)',
        href: 'https://security.snyk.io/vuln/SNYK-PHP-SIMPLESAMLPHPSAML2-8449140',
      },
    ],
  },

  WantAssertionsSigned: {
    purpose:
      'Boolean attribute on the SP\'s `<SPSSODescriptor>` in metadata ' +
      'declaring whether the SP requires the IdP to sign Assertions ' +
      '(in addition to or instead of signing the enclosing Response).',
    withoutIt:
      '`WantAssertionsSigned=false` (often the default) means the SP ' +
      'accepts an unsigned Assertion as long as the enclosing Response ' +
      'is signed. That sounds equivalent — and it is the *single biggest ' +
      'configuration trap in SAML deployments*. With only the Response ' +
      'signed, XSW attacks become trivial: the attacker swaps the ' +
      'Assertion inside an unchanged Response wrapper and the signature ' +
      'still verifies (because the Response\'s signature didn\'t cover the ' +
      'Assertion bytes).',
    attack:
      'XSW exploiting Response-only signing. The IdP signs only the ' +
      '`<Response>` element, not the inner `<Assertion>`. Mallory ' +
      'intercepts a legitimate Response and replaces the Assertion with ' +
      'one she crafted (her chosen NameID, her chosen attributes). The ' +
      'Response\'s signature still references the Response element — ' +
      'which the verifier validates successfully — but the Assertion ' +
      'inside is now Mallory\'s. Application logic reads the swapped ' +
      'Assertion and authenticates her as anyone she wants. This is the ' +
      'low-effort XSW variant — no clever DOM manipulation needed, just ' +
      '"signing the wrong element".',
    impact:
      'Configuration-driven authentication bypass. Defences: every SP ' +
      'metadata MUST declare `WantAssertionsSigned=true`. Every IdP ' +
      'producing Responses for production SPs MUST sign the Assertion ' +
      '(in addition to or instead of the Response). Auditing tip: parse ' +
      'every SP\'s `SPSSODescriptor` in your federation and flag any ' +
      'with `WantAssertionsSigned=false` or missing.',
    references: [
      {
        label: 'SAML 2.0 Metadata §2.4.2 (WantAssertionsSigned)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
      },
      {
        label: 'WorkOS — Fun with SAML SSO Footguns',
        href: 'https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns',
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
    withoutIt:
      'Choosing `emailAddress` or `unspecified` as the account-matching ' +
      'identifier opens cross-tenant impersonation: in multi-tenant ' +
      'IdPs (Entra ID, multi-domain ADFS) where users in different ' +
      'tenants can share email values, an attacker-controlled tenant ' +
      'can mint Assertions claiming any email address — and SPs ' +
      'matching by email link the attacker into the legitimate user\'s ' +
      'account. The same pattern in OIDC is known as the nOAuth attack ' +
      '(Descope, 2023); the SAML version has the same shape.',
    attack:
      'Cross-tenant identifier confusion. Mallory operates her own ' +
      'tenant in a multi-tenant IdP federated with the target SP. She ' +
      'creates a user in her tenant with email ' +
      '`alice@victim-corp.com`. She authenticates and the IdP issues a ' +
      'signed Assertion with that email as NameID. The SP, matching ' +
      'users by email, links Mallory\'s sign-in to Alice\'s legitimate ' +
      'account. Cryptography is fine; the failure is in trusting a ' +
      'mutable identifier as a primary key.',
    impact:
      'Cross-tenant account takeover. Defences: SP MUST request and ' +
      'match by `persistent` NameIDFormat — the IdP issues a stable ' +
      'opaque pseudonym unique to (this user, this SP), with no ' +
      'cross-tenant collision. Use `(Issuer, NameID)` as the composite ' +
      'primary key. `transient` is for stateless single-session use; ' +
      '`emailAddress` is for non-security-critical applications.',
    references: [
      {
        label: 'SAML 2.0 Core §3.4.1.1 (NameIDPolicy)',
        href: 'http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
      },
      {
        label: 'Descope nOAuth disclosure (same pattern, OIDC context)',
        href: 'https://www.descope.com/blog/post/noauth',
      },
    ],
  },
}
