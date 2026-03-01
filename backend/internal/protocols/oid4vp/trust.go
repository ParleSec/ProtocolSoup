package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TrustResolver resolves verifier trust material based on client_id scheme rules.
type TrustResolver interface {
	ResolveVerifier(ctx context.Context, clientID string) (*ResolvedVerifier, error)
	SupportsScheme(scheme ClientIDScheme) bool
}

// ResolvedVerifier captures minimal trust-resolution output used by verification paths.
type ResolvedVerifier struct {
	ClientID       string         `json:"client_id"`
	Scheme         ClientIDScheme `json:"scheme"`
	Subject        string         `json:"subject"`
	DIDDocumentURL string         `json:"did_document_url,omitempty"`
	ResolvedAt     time.Time      `json:"resolved_at"`
}

// DIDWebResolver resolves decentralized_identifier:did:web client IDs for MVP.
type DIDWebResolver struct {
	allowedHosts map[string]struct{}
	httpClient   *http.Client
}

// NewDIDWebResolver creates a resolver with an optional host allowlist.
func NewDIDWebResolver(allowedHosts []string) *DIDWebResolver {
	return NewDIDWebResolverWithClient(allowedHosts, &http.Client{
		Timeout: 5 * time.Second,
	})
}

// NewDIDWebResolverWithClient creates a resolver with explicit HTTP client configuration.
func NewDIDWebResolverWithClient(allowedHosts []string, client *http.Client) *DIDWebResolver {
	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	hostSet := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if normalized == "" {
			continue
		}
		hostSet[normalized] = struct{}{}
	}
	return &DIDWebResolver{
		allowedHosts: hostSet,
		httpClient:   httpClient,
	}
}

// SupportsScheme indicates whether this resolver can handle the given client_id scheme.
func (r *DIDWebResolver) SupportsScheme(scheme ClientIDScheme) bool {
	return scheme == ClientIDSchemeDecentralizedIdentifier
}

// ResolveVerifier resolves a decentralized_identifier client_id to a did:web document URL.
func (r *DIDWebResolver) ResolveVerifier(ctx context.Context, clientID string) (*ResolvedVerifier, error) {
	_ = ctx

	scheme, err := ParseClientIDScheme(clientID)
	if err != nil {
		return nil, err
	}
	if !r.SupportsScheme(scheme) {
		return nil, fmt.Errorf("resolver does not support client_id scheme %q", scheme)
	}

	did := strings.TrimPrefix(strings.TrimSpace(clientID), string(ClientIDSchemeDecentralizedIdentifier)+":")
	documentURL, host, err := DIDWebDocumentURL(did)
	if err != nil {
		return nil, err
	}

	if len(r.allowedHosts) > 0 {
		if _, ok := r.allowedHosts[strings.ToLower(host)]; !ok {
			return nil, fmt.Errorf("did:web host %q is not allowed by resolver policy", host)
		}
	}

	if err := r.validateDIDDocument(ctx, did, documentURL); err != nil {
		return nil, err
	}

	return &ResolvedVerifier{
		ClientID:       clientID,
		Scheme:         scheme,
		Subject:        did,
		DIDDocumentURL: documentURL,
		ResolvedAt:     time.Now().UTC(),
	}, nil
}

func (r *DIDWebResolver) validateDIDDocument(ctx context.Context, did string, documentURL string) error {
	if r.httpClient == nil {
		return fmt.Errorf("resolver http client is unavailable")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if err != nil {
		return fmt.Errorf("build did:web document request: %w", err)
	}
	req.Header.Set("Accept", "application/did+ld+json, application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch did:web document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("did:web document request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read did:web document body: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode did:web document: %w", err)
	}

	docID, _ := payload["id"].(string)
	if strings.TrimSpace(docID) == "" {
		return fmt.Errorf("did:web document is missing id")
	}
	if strings.TrimSpace(docID) != did {
		return fmt.Errorf("did:web document id mismatch: expected %q got %q", did, docID)
	}

	if !hasDIDVerificationMaterial(payload) {
		return fmt.Errorf("did:web document is missing authentication/assertion verification material")
	}
	return nil
}

func hasDIDVerificationMaterial(payload map[string]interface{}) bool {
	if payload == nil {
		return false
	}
	if hasNonEmptyVerificationValue(payload["authentication"]) {
		return true
	}
	if hasNonEmptyVerificationValue(payload["assertionMethod"]) {
		return true
	}
	return hasNonEmptyVerificationValue(payload["verificationMethod"])
}

func hasNonEmptyVerificationValue(raw interface{}) bool {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case []interface{}:
		return len(value) > 0
	case map[string]interface{}:
		return len(value) > 0
	default:
		return false
	}
}

// DIDWebDocumentURL converts a did:web identifier to its DID Document URL.
func DIDWebDocumentURL(did string) (string, string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", "", fmt.Errorf("did must start with did:web:")
	}

	identifier := strings.TrimPrefix(did, "did:web:")
	if identifier == "" {
		return "", "", fmt.Errorf("did:web identifier must include a host")
	}

	segments := strings.Split(identifier, ":")
	if len(segments) == 0 {
		return "", "", fmt.Errorf("did:web identifier is invalid")
	}

	encodedHost := segments[0]
	if encodedHost == "" {
		return "", "", fmt.Errorf("did:web host is required")
	}
	host, err := url.PathUnescape(encodedHost)
	if err != nil {
		return "", "", fmt.Errorf("decode did:web host: %w", err)
	}
	if strings.ContainsAny(host, "/?#") {
		return "", "", fmt.Errorf("did:web host contains invalid characters")
	}

	path := "/.well-known/did.json"
	if len(segments) > 1 {
		pathSegments := make([]string, 0, len(segments)-1)
		for _, raw := range segments[1:] {
			decoded, err := url.PathUnescape(raw)
			if err != nil {
				return "", "", fmt.Errorf("decode did:web path segment: %w", err)
			}
			if decoded == "" || strings.Contains(decoded, "/") {
				return "", "", fmt.Errorf("did:web path segment is invalid")
			}
			pathSegments = append(pathSegments, decoded)
		}
		path = "/" + strings.Join(pathSegments, "/") + "/did.json"
	}

	docURL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path,
	}

	return docURL.String(), host, nil
}
