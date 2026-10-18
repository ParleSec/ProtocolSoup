// Package xmldsig applies the SAML profile of W3C XML Signature (SAML Core
// Section 5.4) on top of goxmldsig, signs and verifies HTTP-Redirect query
// strings (SAML Bindings Section 3.4.4.1), and holds each entity's signing
// credentials.
package xmldsig

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Info describes a signature that was found and verified, for display in
// Looking Glass.
type Info struct {
	SignatureMethod  string `json:"signatureMethod"`
	DigestMethod     string `json:"digestMethod"`
	Canonicalization string `json:"canonicalization"`
	ReferenceURI     string `json:"referenceUri"`
}

// ErrUnsigned reports that an element carries no enveloped signature.
var ErrUnsigned = errors.New("element carries no enveloped <ds:Signature>")

// SignEnveloped adds an enveloped <ds:Signature> over el. SAML Core Section
// 5.4.1 requires enveloped signatures, Section 5.4.2 a single same-document
// <ds:Reference> to the root element's ID, and Section 5.4.3 recommends
// Exclusive Canonicalization. The schema places <ds:Signature> immediately
// after <saml:Issuer>.
func SignEnveloped(el *etree.Element, creds *Credentials) error {
	if el.SelectAttrValue("ID", "") == "" {
		return errors.New("element to sign has no ID attribute (SAML Core Section 5.4.2)")
	}
	ctx, err := dsig.NewSigningContext(creds.key, [][]byte{creds.cert.Raw})
	if err != nil {
		return err
	}
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Sign a detached copy that carries every in-scope namespace declaration,
	// so the digest matches what a verifier computes over the element in place.
	detached, err := detach(el)
	if err != nil {
		return err
	}
	signature, err := ctx.ConstructSignature(detached, true)
	if err != nil {
		return fmt.Errorf("construct XML signature: %w", err)
	}

	index := 0
	if issuer := message.Child(el, message.NamespaceSAML, "Issuer"); issuer != nil {
		index = issuer.Index() + 1
	}
	el.InsertChildAt(index, signature)
	return nil
}

// DirectSignature returns el's enveloped <ds:Signature> child, or nil.
func DirectSignature(el *etree.Element) (*etree.Element, error) {
	signatures := message.Children(el, message.NamespaceDS, "Signature")
	switch len(signatures) {
	case 0:
		return nil, nil
	case 1:
		return signatures[0], nil
	default:
		return nil, errors.New("element carries more than one <ds:Signature>")
	}
}

// VerifyEnveloped verifies el's enveloped signature against the trusted
// certificates published in the signer's metadata and returns the verified
// element. Callers MUST read message content only from the returned element:
// it is rebuilt from the exact bytes covered by the digest, which is what
// defeats XML Signature Wrapping.
func VerifyEnveloped(el *etree.Element, trusted []*x509.Certificate) (*etree.Element, *Info, error) {
	sigEl, err := DirectSignature(el)
	if err != nil {
		return nil, nil, err
	}
	if sigEl == nil {
		return nil, nil, ErrUnsigned
	}
	if len(trusted) == 0 {
		return nil, nil, errors.New("no signing certificate is published in the signer's metadata")
	}

	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return nil, nil, errors.New("signed element has no ID attribute (SAML Core Section 5.4.2)")
	}
	top := el
	for top.Parent() != nil {
		top = top.Parent()
	}
	if count := countIDDeclarations(top, id); count != 1 {
		return nil, nil, fmt.Errorf("ID %q is declared %d times; SAML Core Section 1.3.4 requires exactly one declaration", id, count)
	}

	info, err := inspect(sigEl, id)
	if err != nil {
		return nil, nil, err
	}

	detached, err := detach(el)
	if err != nil {
		return nil, nil, err
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: trusted})
	verified, err := ctx.Validate(detached)
	if err != nil {
		return nil, info, fmt.Errorf("signature verification failed: %w", err)
	}
	return verified, info, nil
}

// detach copies el with every in-scope namespace declaration made explicit.
func detach(el *etree.Element) (*etree.Element, error) {
	parentCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	return etreeutils.NSDetatch(parentCtx, el)
}

// inspect enforces the SAML profile of XML Signature before the
// cryptographic check runs.
func inspect(sigEl *etree.Element, id string) (*Info, error) {
	ds := message.NamespaceDS
	info := &Info{}
	signedInfo := message.Child(sigEl, ds, "SignedInfo")
	if signedInfo == nil {
		return nil, errors.New("<ds:Signature> has no <ds:SignedInfo>")
	}
	if c14n := message.Child(signedInfo, ds, "CanonicalizationMethod"); c14n != nil {
		info.Canonicalization = c14n.SelectAttrValue("Algorithm", "")
	}
	if method := message.Child(signedInfo, ds, "SignatureMethod"); method != nil {
		info.SignatureMethod = method.SelectAttrValue("Algorithm", "")
	}

	// SAML Core Section 5.4.2: a single <ds:Reference> whose URI is "#" + ID.
	references := message.Children(signedInfo, ds, "Reference")
	if len(references) != 1 {
		return info, fmt.Errorf("<ds:SignedInfo> contains %d <ds:Reference> elements; SAML Core Section 5.4.2 requires exactly one", len(references))
	}
	reference := references[0]
	info.ReferenceURI = reference.SelectAttrValue("URI", "")
	if info.ReferenceURI != "#"+id {
		return info, fmt.Errorf("<ds:Reference> URI is %q; SAML Core Section 5.4.2 requires %q", info.ReferenceURI, "#"+id)
	}
	if digest := message.Child(reference, ds, "DigestMethod"); digest != nil {
		info.DigestMethod = digest.SelectAttrValue("Algorithm", "")
	}

	// SAML Core Section 5.4.4: verifiers MAY reject transforms other than the
	// enveloped-signature and exclusive canonicalization transforms.
	if transforms := message.Child(reference, ds, "Transforms"); transforms != nil {
		for _, transform := range transforms.ChildElements() {
			switch alg := transform.SelectAttrValue("Algorithm", ""); alg {
			case string(dsig.EnvelopedSignatureAltorithmId),
				string(dsig.CanonicalXML10ExclusiveAlgorithmId),
				string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId):
			default:
				return info, fmt.Errorf("transform %q is not accepted (SAML Core Section 5.4.4)", alg)
			}
		}
	}

	// SAML Core Section 5.4.5 (Errata E91): verifiers SHOULD reject
	// signatures that contain a <ds:Object> element.
	if message.Child(sigEl, ds, "Object") != nil {
		return info, errors.New("<ds:Signature> contains a <ds:Object> element (SAML Core Section 5.4.5, Errata E91)")
	}
	return info, nil
}

func countIDDeclarations(root *etree.Element, id string) int {
	count := 0
	var walk func(*etree.Element)
	walk = func(el *etree.Element) {
		for _, attr := range el.Attr {
			if attr.Space == "" && attr.Key == "ID" && attr.Value == id {
				count++
			}
		}
		for _, child := range el.ChildElements() {
			walk(child)
		}
	}
	walk(root)
	return count
}
