// Package binding carries SAML protocol messages over HTTP: the HTTP-Redirect
// binding (SAML Bindings Section 3.4) and the HTTP-POST binding (Section 3.5),
// the RelayState rules, and authentication of a received message by its
// signature and Destination.
package binding

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

const (
	ParamSAMLRequest  = "SAMLRequest"
	ParamSAMLResponse = "SAMLResponse"
	ParamRelayState   = "RelayState"
	paramSigAlg       = "SigAlg"
	paramSignature    = "Signature"

	// MaxRelayStateBytes is the limit from SAML Bindings Sections 3.4.3 and
	// 3.5.3: "The value MUST NOT exceed 80 bytes in length".
	MaxRelayStateBytes = 80

	// maxMessageBytes bounds a decoded (and, for Redirect, inflated) message.
	maxMessageBytes = 256 * 1024
)

// Received is a SAML protocol message as it arrived over a binding.
type Received struct {
	Binding    string
	Param      string // SAMLRequest or SAMLResponse
	RelayState string
	XML        []byte
	Root       *etree.Element

	// HTTP-Redirect only (SAML Bindings Section 3.4.4.1).
	SigAlg       string
	Signature    string
	SignedOctets string
}

// Outbound is a protocol message an entity is about to send.
type Outbound struct {
	Element    *etree.Element
	Location   string
	Binding    string
	Param      string
	RelayState string
}

// CheckRelayState enforces the 80-byte RelayState limit.
func CheckRelayState(relayState string) error {
	if len(relayState) > MaxRelayStateBytes {
		return fmt.Errorf("RelayState is %d bytes; SAML Bindings Sections 3.4.3 and 3.5.3 limit it to %d", len(relayState), MaxRelayStateBytes)
	}
	return nil
}

// ============================================================================
// HTTP-Redirect binding (SAML Bindings Section 3.4)
// ============================================================================

// RedirectURL encodes msg per SAML Bindings Section 3.4.4.1: the message is
// sent without an XML signature, DEFLATE-compressed, base64-encoded and
// URL-encoded, and the query string itself is signed with SigAlg/Signature.
func RedirectURL(location, param string, msg *etree.Element, relayState string, creds *xmldsig.Credentials) (string, error) {
	if err := CheckRelayState(relayState); err != nil {
		return "", err
	}
	if sig, _ := xmldsig.DirectSignature(msg); sig != nil {
		return "", errors.New("HTTP-Redirect messages must not carry an XML signature (SAML Bindings Section 3.4.4.1)")
	}
	xmlBytes, err := message.Serialize(msg)
	if err != nil {
		return "", err
	}
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(xmlBytes); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	// The signed octet string is SAMLRequest=...&RelayState=...&SigAlg=...
	// with each value URL-encoded exactly as it appears in the final URL.
	query := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))
	if relayState != "" {
		query += "&" + ParamRelayState + "=" + url.QueryEscape(relayState)
	}
	query += "&" + paramSigAlg + "=" + url.QueryEscape(xmldsig.SigAlgRSASHA256)
	signature, err := xmldsig.SignRedirectOctets(query, creds)
	if err != nil {
		return "", err
	}
	query += "&" + paramSignature + "=" + url.QueryEscape(signature)

	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}
	return location + separator + query, nil
}

// DecodeRedirect reads a Redirect-binding message, keeping the original
// URL-encoded values so the signature can be verified over them: "The relying
// party MUST therefore perform the verification step using the original
// URL-encoded values it received on the query string" (Section 3.4.4.1).
func DecodeRedirect(rawQuery string) (*Received, error) {
	raw := map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(key)
		if err != nil {
			return nil, fmt.Errorf("malformed query parameter name %q", key)
		}
		switch name {
		case ParamSAMLRequest, ParamSAMLResponse, ParamRelayState, paramSigAlg, paramSignature:
			if _, dup := raw[name]; dup {
				return nil, fmt.Errorf("query parameter %s appears more than once", name)
			}
			raw[name] = value
		}
	}

	msg := &Received{Binding: message.BindingHTTPRedirect}
	_, hasRequest := raw[ParamSAMLRequest]
	_, hasResponse := raw[ParamSAMLResponse]
	switch {
	case hasRequest && hasResponse:
		return nil, errors.New("query carries both SAMLRequest and SAMLResponse")
	case hasRequest:
		msg.Param = ParamSAMLRequest
	case hasResponse:
		msg.Param = ParamSAMLResponse
	default:
		return nil, errors.New("query carries neither SAMLRequest nor SAMLResponse")
	}

	decoded := map[string]string{}
	for name, value := range raw {
		unescaped, err := url.QueryUnescape(value)
		if err != nil {
			return nil, fmt.Errorf("query parameter %s is not URL-encoded correctly", name)
		}
		decoded[name] = unescaped
	}
	msg.RelayState = decoded[ParamRelayState]
	if err := CheckRelayState(msg.RelayState); err != nil {
		return nil, err
	}

	if sigAlgRaw, ok := raw[paramSigAlg]; ok {
		if _, ok := raw[paramSignature]; !ok {
			return nil, errors.New("query carries SigAlg without Signature")
		}
		msg.SigAlg = decoded[paramSigAlg]
		msg.Signature = decoded[paramSignature]
		octets := msg.Param + "=" + raw[msg.Param]
		if relayRaw, ok := raw[ParamRelayState]; ok {
			octets += "&" + ParamRelayState + "=" + relayRaw
		}
		msg.SignedOctets = octets + "&" + paramSigAlg + "=" + sigAlgRaw
	} else if _, ok := raw[paramSignature]; ok {
		return nil, errors.New("query carries Signature without SigAlg")
	}

	compressed, err := base64.StdEncoding.DecodeString(stripWhitespace(decoded[msg.Param]))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", msg.Param, err)
	}
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), maxMessageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid DEFLATE data: %w", msg.Param, err)
	}
	if len(inflated) > maxMessageBytes {
		return nil, fmt.Errorf("%s inflates beyond %d bytes", msg.Param, maxMessageBytes)
	}
	msg.XML = inflated
	if msg.Root, err = message.Parse(inflated); err != nil {
		return nil, err
	}
	return msg, nil
}

// ============================================================================
// HTTP-POST binding (SAML Bindings Section 3.5)
// ============================================================================

// postFormTemplate renders the XHTML document SAML Bindings Section 3.5.4
// requires. html/template escapes the control values into HTML entities.
var postFormTemplate = template.Must(template.New("postForm").Parse(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>SAML HTTP-POST binding</title>
</head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.Action}}">
<div>
<input type="hidden" name="{{.Param}}" value="{{.Message}}" />
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />
{{end}}<noscript><p><input type="submit" value="Continue" /></p></noscript>
</div>
</form>
</body>
</html>
`))

// WritePostForm signs msg (enveloped, SAML Core Section 5.4.1) and writes the
// auto-submitting form that delivers it to action.
func WritePostForm(w http.ResponseWriter, action, param string, msg *etree.Element, relayState string, creds *xmldsig.Credentials) ([]byte, error) {
	if err := CheckRelayState(relayState); err != nil {
		return nil, err
	}
	xmlBytes, err := SignedPostXML(msg, creds)
	if err != nil {
		return nil, err
	}
	var page bytes.Buffer
	if err := postFormTemplate.Execute(&page, map[string]string{
		"Action":     action,
		"Param":      param,
		"Message":    base64.StdEncoding.EncodeToString(xmlBytes),
		"RelayState": relayState,
	}); err != nil {
		return nil, err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err = w.Write(page.Bytes())
	return xmlBytes, err
}

// SignedPostXML signs msg with an enveloped signature, unless it already
// carries one, and returns the exact bytes the form carries.
func SignedPostXML(msg *etree.Element, creds *xmldsig.Credentials) ([]byte, error) {
	if sig, err := xmldsig.DirectSignature(msg); err != nil {
		return nil, err
	} else if sig == nil {
		if err := xmldsig.SignEnveloped(msg, creds); err != nil {
			return nil, err
		}
	}
	return message.Serialize(msg)
}

// PostMessage wraps bytes produced by SignedPostXML as if they had arrived
// over HTTP-POST.
func PostMessage(param string, xmlBytes []byte, relayState string) (*Received, error) {
	root, err := message.Parse(xmlBytes)
	if err != nil {
		return nil, err
	}
	return &Received{Binding: message.BindingHTTPPost, Param: param, RelayState: relayState, XML: xmlBytes, Root: root}, nil
}

// DecodePost reads a POST-binding message from the form body.
func DecodePost(r *http.Request) (*Received, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 2*maxMessageBytes)
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("form body could not be parsed: %w", err)
	}
	relayState := r.PostForm.Get(ParamRelayState)
	request, response := r.PostForm.Get(ParamSAMLRequest), r.PostForm.Get(ParamSAMLResponse)
	var param, encoded string
	switch {
	case request != "" && response != "":
		return nil, errors.New("form carries both SAMLRequest and SAMLResponse")
	case request != "":
		param, encoded = ParamSAMLRequest, request
	case response != "":
		param, encoded = ParamSAMLResponse, response
	default:
		return nil, errors.New("form carries neither SAMLRequest nor SAMLResponse")
	}
	if err := CheckRelayState(relayState); err != nil {
		return nil, err
	}
	// Section 3.5.4: "The base64-encoded value MAY be line-wrapped".
	xmlBytes, err := base64.StdEncoding.DecodeString(stripWhitespace(encoded))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", param, err)
	}
	if len(xmlBytes) > maxMessageBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", param, maxMessageBytes)
	}
	return PostMessage(param, xmlBytes, relayState)
}

// Decode picks the binding from the HTTP method: GET is HTTP-Redirect, POST is
// HTTP-POST.
func Decode(r *http.Request) (*Received, error) {
	if r.Method == http.MethodPost {
		return DecodePost(r)
	}
	return DecodeRedirect(r.URL.RawQuery)
}

// Send delivers out over its binding and returns the XML that went on the wire:
// signed for HTTP-POST, unsigned for HTTP-Redirect, whose signature is on the
// query string.
//
// When r carries a Looking Glass capture session, the endpoint URL the user
// agent is sent to carries it on as lg_session, so the next hop is captured
// too. It sits outside the signed values (Bindings Section 3.4.4.1: "Any other
// content in the original query string is not included and not signed") and
// outside the Destination attribute, which names the endpoint itself.
func Send(w http.ResponseWriter, r *http.Request, out *Outbound, creds *xmldsig.Credentials) ([]byte, error) {
	endpoint := WithSession(r, out.Location)
	if out.Binding == message.BindingHTTPRedirect {
		location, err := RedirectURL(endpoint, out.Param, out.Element, out.RelayState, creds)
		if err != nil {
			return nil, err
		}
		xmlBytes, err := message.Serialize(out.Element)
		if err != nil {
			return nil, err
		}
		http.Redirect(w, r, location, http.StatusFound)
		return xmlBytes, nil
	}
	return WritePostForm(w, endpoint, out.Param, out.Element, out.RelayState, creds)
}

// WithSession adds r's Looking Glass capture session to location as
// lg_session, or returns location unchanged when r carries none.
func WithSession(r *http.Request, location string) string {
	sessionID := LookingGlassSession(r)
	if sessionID == "" {
		return location
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return location
	}
	query := parsed.Query()
	query.Set("lg_session", sessionID)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// FromQuery maps a "binding" query value ("post" or "redirect") to a binding
// identifier, or fallback.
func FromQuery(r *http.Request, fallback string) string {
	switch r.URL.Query().Get("binding") {
	case "post":
		return message.BindingHTTPPost
	case "redirect":
		return message.BindingHTTPRedirect
	}
	return fallback
}

func stripWhitespace(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, value)
}

// DecodeBase64 decodes a base64 SAML message value, ignoring line wrapping.
func DecodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stripWhitespace(value))
}

// WriteJSON writes v as an uncached JSON response.
func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
