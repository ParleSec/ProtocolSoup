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

// IMPORTANT: Store requestId (server side) for InResponseTo validation when the
// Response arrives, together with the RelayState sent with it.
// RelayState is an opaque value of at most 80 bytes (saml-bindings §3.4.3),
// not the target URL itself; keep the target URL in server-side state.
const relayState = crypto.randomUUID();
pendingRequests.set(requestId, { relayState, targetUrl: TARGET_URL });

// Step 2a: HTTP-Redirect binding (saml-bindings §3.4.4.1)
// The XML is sent WITHOUT a <ds:Signature>; DEFLATE-compress, Base64-encode,
// URL-encode. When the SP signs its requests (AuthnRequestsSigned="true" in
// its metadata), the signature covers the query string, in this order:
const deflated = pako.deflateRaw(new TextEncoder().encode(authnRequest));
const encoded = btoa(String.fromCharCode(...deflated));
const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const signedQuery = 'SAMLRequest=' + encodeURIComponent(encoded)
  + '&RelayState=' + encodeURIComponent(relayState)
  + '&SigAlg=' + encodeURIComponent(sigAlg);
const signature = await signRsaSha256(SP_SIGNING_KEY, signedQuery); // base64
window.location.href = IDP_SSO_URL + '?' + signedQuery
  + '&Signature=' + encodeURIComponent(signature);

// Step 2b: HTTP-POST binding (saml-bindings §3.5)
// Sign the XML with an enveloped <ds:Signature> placed after <saml:Issuer>
// (exclusive C14N, saml-core §5.4), Base64-encode it (no DEFLATE), and submit
// via an auto-posting form. Escape the values for HTML.
const postEncoded = btoa(signEnveloped(authnRequest, SP_SIGNING_KEY));
document.body.innerHTML = \`
<form method="POST" action="\${IDP_SSO_URL}">
  <input type="hidden" name="SAMLRequest" value="\${postEncoded}"/>
  <input type="hidden" name="RelayState" value="\${relayState}"/>
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

// The SP's assertion consumer service receives the Response over HTTP-POST
// (the HTTP-Redirect binding MUST NOT carry a <Response>, saml-profiles §4.1.2).

// Step 1: Decode the SAML Response exactly as received
const xml = atob(formData.get('SAMLResponse'));

// Step 2: Verify the signature, then read ONLY what it covers.
// verifyEnvelopedSignature must trust only the certificate from the IdP's
// metadata (never one carried in <ds:KeyInfo>), require a single <ds:Reference>
// to "#" + the element's ID (saml-core §5.4.2), reject an ID declared twice,
// and return the signed element. Reading <Assertion> from the whole document
// after checking "a" signature is how XML Signature Wrapping attacks succeed.
const assertion = await verifyEnvelopedSignature(xml, 'Assertion', idpMetadata.signingCerts);

// Step 3: Validate the verified assertion (saml-profiles §4.1.4.2-§4.1.4.3)
const CLOCK_SKEW = 3 * 60 * 1000; // saml-core §1.3.3 (Errata E92): 3-5 minutes
const now = Date.now();
if (assertion.issuer !== idpMetadata.entityID) throw new Error('Issuer mismatch');

// 3a. A bearer SubjectConfirmation addressed to this ACS. In an unsolicited
//     Response, InResponseTo MUST NOT be present (saml-profiles §4.1.5).
const scd = assertion.bearerSubjectConfirmationData;
if (scd.recipient !== SP_ACS_URL) throw new Error('Recipient mismatch');
if (now >= Date.parse(scd.notOnOrAfter) + CLOCK_SKEW) throw new Error('Subject confirmation expired');
if (scd.inResponseTo) throw new Error('Unsolicited Response carries InResponseTo');

// 3b. Conditions (saml-core §2.5.1): time window and every AudienceRestriction
if (now + CLOCK_SKEW < Date.parse(assertion.conditions.notBefore)) throw new Error('Not yet valid');
if (now >= Date.parse(assertion.conditions.notOnOrAfter) + CLOCK_SKEW) throw new Error('Expired');
if (!assertion.conditions.audienceRestrictions.every((audiences) => audiences.includes(SP_ENTITY_ID))) {
  throw new Error('This SP is not in every AudienceRestriction');
}

// 3c. Replay detection (saml-profiles §4.1.4.5). With no AuthnRequest to
//     correlate, this is the SP's main defence. Keep each ID until its
//     SubjectConfirmationData NotOnOrAfter has passed.
if (consumedAssertionIds.has(assertion.id)) throw new Error('Assertion replay detected');
consumedAssertionIds.set(assertion.id, Date.parse(scd.notOnOrAfter) + CLOCK_SKEW);

// Step 4: Create the local session; keep NameID and SessionIndex for Single Logout
const { nameId, sessionIndex } = assertion;`,
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
    Destination="\${IDP_SLO_URL}"
    NotOnOrAfter="\${new Date(Date.now() + 5 * 60 * 1000).toISOString()}">
  <saml:Issuer>\${SP_ENTITY_ID}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    \${userEmail}
  </saml:NameID>
  <samlp:SessionIndex>\${sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>\`;

// Send via HTTP-Redirect (DEFLATE + Base64). "The <LogoutRequest> message MUST
// be signed if the HTTP POST or Redirect binding is used" (saml-profiles
// §4.4.3.1); on Redirect the signature covers the query string.
const deflated = pako.deflateRaw(new TextEncoder().encode(logoutRequest));
const encoded = btoa(String.fromCharCode(...deflated));
const relayState = crypto.randomUUID(); // opaque, at most 80 bytes
const signedQuery = 'SAMLRequest=' + encodeURIComponent(encoded)
  + '&RelayState=' + encodeURIComponent(relayState)
  + '&SigAlg=' + encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
const signature = await signRsaSha256(SP_SIGNING_KEY, signedQuery);
window.location.href = IDP_SLO_URL + '?' + signedQuery
  + '&Signature=' + encodeURIComponent(signature);

// === IdP-side: Process LogoutRequest ===
// 1. IdP receives LogoutRequest, identifies the user by NameID
// 2. IdP finds ALL sessions for this user across ALL SPs
// 3. IdP sends LogoutRequest to each participating SP (fan-out)
// 4. Each SP destroys its local session, responds with LogoutResponse
// 5. IdP sends final LogoutResponse to the initiating SP

// === SP-side: Receive LogoutResponse ===
// Validate: the signature, against the IdP certificate from its metadata
// Validate: Issuer is the IdP; Destination is this SingleLogoutService
// Validate: InResponseTo matches the ID of our LogoutRequest; RelayState matches
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

<!-- SP Metadata, published at its entityID URL (saml-metadata §4.1.1) -->
<!-- and served as application/samlmetadata+xml -->
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://sp.example.com/saml/metadata"
    validUntil="2026-12-31T00:00:00Z"
    cacheDuration="PT1H">
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

    <!-- Single Logout Service — where IdP sends LogoutRequest/Response -->
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sp.example.com/saml/slo"/>

    <!-- NameID formats this SP accepts -->
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>

    <!-- Assertion Consumer Service — where IdP POSTs the SAML Response. -->
    <!-- The schema orders it after SingleLogoutService and NameIDFormat. -->
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/saml/acs"
        index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>

<!-- To consume IdP metadata, dereference the IdP's entityID:  -->
<!-- const response = await fetch(IDP_ENTITY_ID);               -->
<!-- (ProtocolSoup's IdP publishes at /saml/idp/metadata)       -->
<!-- const xml = await response.text();                        -->
<!-- Parse SSO endpoint, SLO endpoint, and signing certificate -->
<!-- from the IdP's EntityDescriptor / IDPSSODescriptor.       -->`,
  },
}
