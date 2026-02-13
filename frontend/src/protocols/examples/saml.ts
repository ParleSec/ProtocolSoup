import type { CodeExample } from './index'

export const SAML_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  sp_initiated_sso: {
    language: 'javascript',
    label: 'JavaScript / XML (Service Provider)',
    code: `// SAML 2.0 SP-Initiated SSO (saml-profiles §4.1.4)
// The Service Provider creates an AuthnRequest and sends it to the IdP.

// Step 1: Construct the AuthnRequest XML (saml-core §3.4.1)
const requestId = '_' + crypto.randomUUID();  // MUST start with letter or underscore
const authnRequest = \`
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="\${requestId}"
    Version="2.0"
    IssueInstant="\${new Date().toISOString()}"
    Destination="\${IDP_SSO_URL}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="\${SP_ACS_URL}">
  <saml:Issuer>\${SP_ENTITY_ID}</saml:Issuer>
  <samlp:NameIDPolicy
      Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      AllowCreate="true"/>
</samlp:AuthnRequest>\`;

// IMPORTANT: Store requestId for InResponseTo validation when the Response arrives.
// This prevents replay attacks and unsolicited response injection.
sessionStorage.setItem('saml_request_id', requestId);

// Step 2a: HTTP-Redirect binding (saml-bindings §3.4)
// DEFLATE-compress, Base64-encode, URL-encode
const deflated = pako.deflateRaw(new TextEncoder().encode(authnRequest));
const encoded = btoa(String.fromCharCode(...deflated));
const redirectUrl = IDP_SSO_URL
  + '?SAMLRequest=' + encodeURIComponent(encoded)
  + '&RelayState=' + encodeURIComponent(TARGET_URL);
// Optionally append SigAlg + Signature for signed redirect requests
window.location.href = redirectUrl;

// Step 2b: HTTP-POST binding (saml-bindings §3.5)
// Base64-encode the raw XML (no DEFLATE) and submit via auto-posting form
const postEncoded = btoa(authnRequest);
document.body.innerHTML = \`
<form method="POST" action="\${IDP_SSO_URL}">
  <input type="hidden" name="SAMLRequest" value="\${postEncoded}"/>
  <input type="hidden" name="RelayState" value="\${TARGET_URL}"/>
</form>\`;
document.forms[0].submit();`,
  },

  /* ------------------------------------------------------------------ */
  idp_initiated_sso: {
    language: 'javascript',
    label: 'JavaScript / XML (Service Provider — Receiver)',
    code: `// SAML 2.0 IdP-Initiated SSO (saml-profiles §4.1.5)
// The IdP sends an unsolicited SAML Response — no AuthnRequest was issued.
// ⚠️  This flow has weaker security properties than SP-initiated SSO.

// The SP receives a SAML Response via HTTP-POST without a prior AuthnRequest:
// <form method="POST" action="/saml/acs">
//   <input name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNl..." />
//   <input name="RelayState" value="https://app.example.com/dashboard" />
// </form>

// Step 1: Decode and parse the SAML Response
const samlResponseB64 = formData.get('SAMLResponse');
const xml = atob(samlResponseB64);
const parser = new DOMParser();
const doc = parser.parseFromString(xml, 'application/xml');

// Step 2: Validate the Response (saml-profiles §4.1.4.3)
// The IdP-initiated flow SKIPS InResponseTo validation because
// no AuthnRequest was issued. This is the key security trade-off.

// 2a. Verify XML Digital Signature (xmldsig-core §3)
//     - Validate <ds:Signature> using IdP certificate from metadata
//     - Check SignedInfo references cover the Assertion or Response
const signature = doc.querySelector('Signature');
await verifyXMLSignature(signature, idpCertificate);

// 2b. InResponseTo: SKIPPED (no request was issued)
//     This is the primary weakness — without a request-response binding,
//     the SP cannot detect replayed responses via request correlation.

// 2c. Assertion replay detection (CRITICAL for IdP-initiated)
//     Cache Assertion IDs to detect reuse. This is the SP's ONLY defense
//     against replay attacks in the IdP-initiated flow.
const assertionId = doc.querySelector('Assertion')?.getAttribute('ID');
if (consumedAssertionIds.has(assertionId)) {
  throw new Error('Assertion replay detected');
}
consumedAssertionIds.add(assertionId);

// 2d. Validate Conditions (saml-core §2.5)
const conditions = doc.querySelector('Conditions');
const notBefore = new Date(conditions.getAttribute('NotBefore'));
const notOnOrAfter = new Date(conditions.getAttribute('NotOnOrAfter'));
const now = new Date();
const CLOCK_SKEW = 5 * 60 * 1000; // 5-minute tolerance
if (now < notBefore.getTime() - CLOCK_SKEW || now > notOnOrAfter.getTime() + CLOCK_SKEW) {
  throw new Error('Assertion conditions not met');
}

// 2e. Validate AudienceRestriction — SP entity ID MUST be listed
const audience = doc.querySelector('AudienceRestriction Audience')?.textContent;
if (audience !== SP_ENTITY_ID) {
  throw new Error('Audience mismatch');
}

// Step 3: Extract identity and create local session
const nameId = doc.querySelector('NameID')?.textContent;
const sessionIndex = doc.querySelector('AuthnStatement')?.getAttribute('SessionIndex');
// Store sessionIndex for Single Logout coordination`,
  },

  /* ------------------------------------------------------------------ */
  single_logout: {
    language: 'javascript',
    label: 'JavaScript / XML (SP or IdP)',
    code: `// SAML 2.0 Single Logout (saml-profiles §4.4)
// Terminates sessions at the IdP AND all participating SPs.

// === SP-Initiated Logout: SP sends LogoutRequest to IdP ===

const logoutRequestId = '_' + crypto.randomUUID();
const logoutRequest = \`
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="\${logoutRequestId}"
    Version="2.0"
    IssueInstant="\${new Date().toISOString()}"
    Destination="\${IDP_SLO_URL}">
  <saml:Issuer>\${SP_ENTITY_ID}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    \${userEmail}
  </saml:NameID>
  <samlp:SessionIndex>\${sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>\`;

// Send via HTTP-Redirect (DEFLATE + Base64)
const deflated = pako.deflateRaw(new TextEncoder().encode(logoutRequest));
const encoded = btoa(String.fromCharCode(...deflated));
window.location.href = IDP_SLO_URL
  + '?SAMLRequest=' + encodeURIComponent(encoded)
  + '&RelayState=' + encodeURIComponent(POST_LOGOUT_URL);

// === IdP-side: Process LogoutRequest ===
// 1. IdP receives LogoutRequest, identifies the user by NameID
// 2. IdP finds ALL sessions for this user across ALL SPs
// 3. IdP sends LogoutRequest to each participating SP (fan-out)
// 4. Each SP destroys its local session, responds with LogoutResponse
// 5. IdP sends final LogoutResponse to the initiating SP

// === SP-side: Receive LogoutResponse ===
// Validate: InResponseTo matches the ID of our LogoutRequest
// Validate: Status is "urn:oasis:names:tc:SAML:2.0:status:Success"
// Destroy local session and redirect to post-logout URL`,
  },

  /* ------------------------------------------------------------------ */
  metadata: {
    language: 'xml',
    label: 'XML (Metadata Document)',
    code: `<!-- SAML 2.0 Metadata Exchange (saml-metadata §2) -->
<!-- Both SP and IdP publish metadata documents that describe their capabilities -->
<!-- and endpoints. These are fetched once and cached for trust establishment. -->

<!-- SP Metadata — published at /saml/metadata -->
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://sp.example.com">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- Signing certificate — IdP uses this to verify AuthnRequest signatures -->
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data><ds:X509Certificate>MIID...</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- Assertion Consumer Service — where IdP POSTs the SAML Response -->
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/saml/acs"
        index="0" isDefault="true"/>

    <!-- Single Logout Service — where IdP sends LogoutRequest/Response -->
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sp.example.com/saml/slo"/>

    <!-- NameID formats this SP accepts -->
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  </md:SPSSODescriptor>
</md:EntityDescriptor>

<!-- To consume IdP metadata programmatically: -->
<!-- const response = await fetch('/saml/metadata');           -->
<!-- const xml = await response.text();                        -->
<!-- Parse SSO endpoint, SLO endpoint, and signing certificate -->
<!-- from the IdP's EntityDescriptor / IDPSSODescriptor.       -->`,
  },
}
