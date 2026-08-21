package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

const (
	clientAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	maxClientAssertionSize     = 8 * 1024
	clientAssertionClockSkew   = 60 * time.Second
	maxClientAssertionLifetime = 300 * time.Second
	clientJWKSCacheTTL         = 10 * time.Minute
	clientJWKSRefetchInterval  = 30 * time.Second
	clientJWKSFetchTimeout     = 3 * time.Second
	maxClientJWKSResponseSize  = 64 * 1024
	demoClientRegistrationTTL  = 10 * time.Minute
)

type clientAssertionError struct {
	reason string
	err    error
}

func (e *clientAssertionError) Error() string {
	if e.err == nil {
		return e.reason
	}
	return e.reason + ": " + e.err.Error()
}

func assertionError(reason string, err ...error) error {
	var cause error
	if len(err) > 0 {
		cause = err[0]
	}
	return &clientAssertionError{reason: reason, err: cause}
}

func clientAssertionFailureReason(err error) string {
	var validationErr *clientAssertionError
	if errors.As(err, &validationErr) {
		return validationErr.reason
	}
	return "client_assertion_validation_failed"
}

type validatedClientAssertion struct {
	algorithm   string
	keyID       string
	jti         string
	replayUntil time.Time
}

// authenticatePrivateKeyJWT validates the RFC 7523 Section 2.2 assertion and
// returns the same client model used by password-based client authentication.
func (p *Plugin) authenticatePrivateKeyJWT(clientID, assertion string) (*models.Client, *validatedClientAssertion, error) {
	return p.AuthenticatePrivateKeyJWTWithAudiences(
		context.Background(),
		clientID,
		assertion,
		[]string{strings.TrimRight(p.baseURL, "/") + "/oauth2/token"},
	)
}

// AuthenticatePrivateKeyJWTWithAudiences validates a private_key_jwt client
// assertion against any of the allowed audience values. OIDC Core Section 9
// permits the token endpoint URL or the issuer identifier.
func (p *Plugin) AuthenticatePrivateKeyJWTWithAudiences(
	ctx context.Context,
	clientID string,
	assertion string,
	audiences []string,
) (*models.Client, *validatedClientAssertion, error) {
	// RFC 7523 / OIDC Core Section 9: client_id may be omitted from the token
	// request when using private_key_jwt; the identifier is carried as iss/sub
	// in the client_assertion JWT. Dynamic OP token requests often omit it.
	if clientID == "" {
		extracted, err := clientIDFromClientAssertion(assertion)
		if err != nil {
			return nil, nil, err
		}
		clientID = extracted
	}
	if clientID == "" {
		return nil, nil, assertionError("missing_client_id")
	}
	if len(audiences) == 0 {
		return nil, nil, assertionError("missing_audience")
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		return nil, nil, assertionError("unknown_client")
	}
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		return nil, nil, assertionError("client_auth_method_not_registered")
	}

	now := p.now()
	var validated *validatedClientAssertion
	var err error
	for _, audience := range audiences {
		_, validated, err = parseAndValidateClientAssertion(assertion, clientID, audience, now)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}

	jwk, err := p.clientKeyResolver.resolve(client, validated.keyID, validated.algorithm)
	if err != nil {
		return nil, nil, assertionError("client_key_resolution_failed", err)
	}
	if err := validateClientAssertionKeyBinding(*jwk, validated.algorithm); err != nil {
		return nil, nil, err
	}

	publicKey, err := jwk.ToPublicKey()
	if err != nil {
		return nil, nil, assertionError("invalid_registered_key", err)
	}
	validSignature, err := internalcrypto.VerifySignatureWithKey(assertion, publicKey)
	if err != nil || !validSignature {
		return nil, nil, assertionError("invalid_signature", err)
	}

	reserved, err := p.clientAssertionReplay.Reserve(
		ctx,
		clientID,
		validated.jti,
		validated.replayUntil,
		now,
	)
	if err != nil {
		return nil, nil, &clientAssertionInfrastructureError{err: err}
	}
	if !reserved {
		return nil, nil, assertionError("replayed_jti")
	}

	return client, validated, nil
}

// clientIDFromClientAssertion reads the client identifier from an unverified
// client_assertion JWT. Signature and claim validation still happen later.
func clientIDFromClientAssertion(assertion string) (string, error) {
	if assertion == "" {
		return "", assertionError("missing_client_assertion")
	}
	decoded, err := internalcrypto.DecodeTokenWithoutValidation(assertion)
	if err != nil {
		return "", assertionError("malformed_client_assertion", err)
	}
	issuer, issuerOK := nonEmptyStringClaim(decoded.Payload, "iss")
	subject, subjectOK := nonEmptyStringClaim(decoded.Payload, "sub")
	if !issuerOK || !subjectOK {
		return "", assertionError("missing_client_id")
	}
	if issuer != subject {
		return "", assertionError("iss_sub_mismatch")
	}
	return issuer, nil
}

func parseAndValidateClientAssertion(
	assertion string,
	expectedClientID string,
	expectedAudience string,
	now time.Time,
) (*internalcrypto.DecodedToken, *validatedClientAssertion, error) {
	if len(assertion) > maxClientAssertionSize {
		return nil, nil, assertionError("assertion_too_large")
	}
	if assertion == "" {
		return nil, nil, assertionError("missing_client_assertion")
	}

	decoded, err := internalcrypto.DecodeTokenWithoutValidation(assertion)
	if err != nil {
		return nil, nil, assertionError("malformed_client_assertion", err)
	}
	if err := restoreExactNumericDateClaims(decoded); err != nil {
		return nil, nil, assertionError("malformed_client_assertion", err)
	}

	algorithm, ok := decoded.Header["alg"].(string)
	if !ok || algorithm == "" {
		return nil, nil, assertionError("missing_alg")
	}
	if algorithm == "none" {
		return nil, nil, assertionError("alg_none_rejected")
	}
	switch algorithm {
	case "RS256", "ES256", "EdDSA":
	default:
		return nil, nil, assertionError("disallowed_alg")
	}

	if _, present := decoded.Header["crit"]; present {
		return nil, nil, assertionError("unsupported_critical_header")
	}
	if _, present := decoded.Header["b64"]; present {
		return nil, nil, assertionError("unsupported_unencoded_payload")
	}
	keyID := ""
	if rawKeyID, present := decoded.Header["kid"]; present {
		var valid bool
		keyID, valid = rawKeyID.(string)
		if !valid || keyID == "" {
			return nil, nil, assertionError("invalid_kid")
		}
	}
	issuer, issuerOK := nonEmptyStringClaim(decoded.Payload, "iss")
	subject, subjectOK := nonEmptyStringClaim(decoded.Payload, "sub")
	if !issuerOK {
		return nil, nil, assertionError("missing_iss")
	}
	if !subjectOK {
		return nil, nil, assertionError("missing_sub")
	}
	if issuer != subject {
		return nil, nil, assertionError("iss_sub_mismatch")
	}
	if expectedClientID == "" {
		return nil, nil, assertionError("missing_client_id")
	}
	if issuer != expectedClientID || subject != expectedClientID {
		return nil, nil, assertionError("client_id_claim_mismatch")
	}

	if !audienceContainsExactly(decoded.Payload["aud"], expectedAudience) {
		return nil, nil, assertionError("invalid_aud")
	}

	issuedAt, ok := numericDateClaim(decoded.Payload, "iat")
	if !ok {
		return nil, nil, assertionError("missing_or_invalid_iat")
	}
	expiresAt, ok := numericDateClaim(decoded.Payload, "exp")
	if !ok {
		return nil, nil, assertionError("missing_or_invalid_exp")
	}
	if expiresAt.Before(issuedAt) {
		return nil, nil, assertionError("invalid_assertion_lifetime")
	}
	if expiresAt.Sub(issuedAt) > maxClientAssertionLifetime {
		return nil, nil, assertionError("assertion_lifetime_exceeds_300_seconds")
	}
	if issuedAt.After(now.Add(clientAssertionClockSkew)) {
		return nil, nil, assertionError("iat_in_future")
	}
	if !now.Before(expiresAt.Add(clientAssertionClockSkew)) {
		return nil, nil, assertionError("assertion_expired")
	}

	if _, present := decoded.Payload["nbf"]; present {
		notBefore, valid := numericDateClaim(decoded.Payload, "nbf")
		if !valid {
			return nil, nil, assertionError("invalid_nbf")
		}
		if notBefore.After(now.Add(clientAssertionClockSkew)) {
			return nil, nil, assertionError("assertion_not_yet_valid")
		}
	}

	jti, ok := nonEmptyStringClaim(decoded.Payload, "jti")
	if !ok {
		return nil, nil, assertionError("missing_jti")
	}

	return decoded, &validatedClientAssertion{
		algorithm: algorithm,
		keyID:     keyID,
		jti:       jti,
		// OIDC Core Section 9 requires one-time use. Keep the replay marker
		// for the entire interval in which clock-skew policy can accept it.
		replayUntil: expiresAt.Add(clientAssertionClockSkew),
	}, nil
}

func nonEmptyStringClaim(claims map[string]interface{}, name string) (string, bool) {
	value, ok := claims[name].(string)
	return value, ok && value != ""
}

func restoreExactNumericDateClaims(decoded *internalcrypto.DecodedToken) error {
	if decoded == nil {
		return errors.New("decoded client assertion is required")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(decoded.PayloadRaw)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	var exactPayload map[string]interface{}
	if err := decoder.Decode(&exactPayload); err != nil {
		return err
	}
	for _, name := range []string{"iat", "exp", "nbf"} {
		if value, present := exactPayload[name]; present {
			decoded.Payload[name] = value
		}
	}
	return nil
}

func numericDateClaim(claims map[string]interface{}, name string) (time.Time, bool) {
	var numericValue float64
	switch value := claims[name].(type) {
	case float64:
		numericValue = value
	case json.Number:
		return exactNumericDate(value)
	case int64:
		return time.Unix(value, 0), true
	case int:
		return time.Unix(int64(value), 0), true
	default:
		return time.Time{}, false
	}
	if math.IsNaN(numericValue) || math.IsInf(numericValue, 0) ||
		numericValue < float64(math.MinInt64) ||
		numericValue >= float64(math.MaxInt64) {
		return time.Time{}, false
	}
	seconds, fractional := math.Modf(numericValue)
	nanoseconds := int64(math.Round(fractional * float64(time.Second)))
	return time.Unix(int64(seconds), nanoseconds), true
}

func exactNumericDate(value json.Number) (time.Time, bool) {
	rational, ok := new(big.Rat).SetString(value.String())
	if !ok {
		return time.Time{}, false
	}
	seconds := new(big.Int)
	remainder := new(big.Int)
	seconds.QuoRem(rational.Num(), rational.Denom(), remainder)
	if !seconds.IsInt64() {
		return time.Time{}, false
	}

	nanosecondNumerator := new(big.Int).Mul(remainder, big.NewInt(int64(time.Second)))
	nanoseconds := new(big.Int)
	nanosecondRemainder := new(big.Int)
	nanoseconds.QuoRem(nanosecondNumerator, rational.Denom(), nanosecondRemainder)
	absoluteRemainder := new(big.Int).Abs(new(big.Int).Set(nanosecondRemainder))
	twiceRemainder := new(big.Int).Lsh(absoluteRemainder, 1)
	if twiceRemainder.Cmp(rational.Denom()) >= 0 {
		if nanosecondNumerator.Sign() < 0 {
			nanoseconds.Sub(nanoseconds, big.NewInt(1))
		} else {
			nanoseconds.Add(nanoseconds, big.NewInt(1))
		}
	}
	if !nanoseconds.IsInt64() {
		return time.Time{}, false
	}
	return time.Unix(seconds.Int64(), nanoseconds.Int64()), true
}

func audienceContainsExactly(raw interface{}, expected string) bool {
	switch value := raw.(type) {
	case string:
		return value == expected
	case []interface{}:
		matched := false
		for _, item := range value {
			audience, ok := item.(string)
			if !ok {
				return false
			}
			if audience == expected {
				matched = true
			}
		}
		return matched
	case []string:
		for _, audience := range value {
			if audience == expected {
				return true
			}
		}
	}
	return false
}

func validateClientAssertionKeyBinding(jwk internalcrypto.JWK, algorithm string) error {
	if internalcrypto.JWKContainsPrivateMaterial(jwk) {
		return assertionError("registered_key_contains_private_material")
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return assertionError("registered_key_not_for_signing")
	}
	if len(jwk.KeyOps) > 0 {
		allowsVerification := false
		for _, operation := range jwk.KeyOps {
			if operation == "verify" {
				allowsVerification = true
				break
			}
		}
		if !allowsVerification {
			return assertionError("registered_key_not_for_verification")
		}
	}
	if jwk.Alg != "" && jwk.Alg != algorithm {
		return assertionError("alg_key_mismatch")
	}

	switch algorithm {
	case "RS256":
		if jwk.Kty != "RSA" {
			return assertionError("alg_key_type_mismatch")
		}
	case "ES256":
		if jwk.Kty != "EC" || jwk.Crv != "P-256" {
			return assertionError("alg_key_type_mismatch")
		}
	case "EdDSA":
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			return assertionError("alg_key_type_mismatch")
		}
	default:
		return assertionError("disallowed_alg")
	}
	return internalcrypto.ValidateJWK(jwk)
}

func clientAssertionReplayKey(clientID, jti string) string {
	return clientID + "\x00" + jti
}

type cachedClientJWKS struct {
	jwks      internalcrypto.JWKS
	fetchedAt time.Time
}

type clientJWKSFetchCall struct {
	done chan struct{}
	jwks *internalcrypto.JWKS
	err  error
}

var errClientJWKUnknownKid = errors.New("unknown kid")

type clientJWKSResolver struct {
	mu           sync.Mutex
	cache        map[string]cachedClientJWKS
	lastRefetch  map[string]time.Time
	inflight     map[string]*clientJWKSFetchCall
	httpClient   *http.Client
	lookupIPs    func(context.Context, string) ([]net.IP, error)
	dialContext  func(context.Context, string, string) (net.Conn, error)
	fetchTimeout time.Duration
	now          func() time.Time
}

func newClientJWKSResolver() *clientJWKSResolver {
	resolver := &clientJWKSResolver{
		cache:        make(map[string]cachedClientJWKS),
		lastRefetch:  make(map[string]time.Time),
		inflight:     make(map[string]*clientJWKSFetchCall),
		fetchTimeout: clientJWKSFetchTimeout,
		now:          time.Now,
	}
	resolver.lookupIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addresses))
		for _, address := range addresses {
			ips = append(ips, address.IP)
		}
		return ips, nil
	}
	dialer := &net.Dialer{}
	resolver.dialContext = dialer.DialContext

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = resolver.secureDialContext
	resolver.httpClient = &http.Client{
		Timeout:   clientJWKSFetchTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("JWKS redirects are not allowed")
		},
	}
	return resolver
}

func (r *clientJWKSResolver) resolve(client *models.Client, kid, algorithm string) (*internalcrypto.JWK, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}

	if client.JWKS != nil {
		key, err := selectClientJWK(*client.JWKS, kid, algorithm)
		if err == nil {
			return key, nil
		}
		// A jwks_uri is fallback only when the requested kid is absent from
		// the static set. Invalid static key material or an ambiguous request
		// must not be bypassed by trying a second registration source.
		if !errors.Is(err, errClientJWKUnknownKid) {
			return nil, err
		}
	}
	if client.JWKSURI == "" {
		return nil, errors.New("no registered key matches the assertion")
	}

	jwks, err := r.fetch(client.ID, client.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	key, selectionErr := selectClientJWK(*jwks, kid, algorithm)
	if selectionErr == nil {
		return key, nil
	}
	if !errors.Is(selectionErr, errClientJWKUnknownKid) {
		return nil, selectionErr
	}

	refetched, err := r.fetch(client.ID, client.JWKSURI, true)
	if err != nil {
		return nil, err
	}
	return selectClientJWK(*refetched, kid, algorithm)
}

func selectClientJWK(jwks internalcrypto.JWKS, kid, algorithm string) (*internalcrypto.JWK, error) {
	for _, key := range jwks.Keys {
		if internalcrypto.JWKContainsPrivateMaterial(key) {
			return nil, errors.New("registered JWKS contains private key material")
		}
	}
	if kid != "" {
		var selected *internalcrypto.JWK
		for index := range jwks.Keys {
			if jwks.Keys[index].Kid == kid {
				key := jwks.Keys[index]
				if selected != nil {
					return nil, errors.New("registered JWKS contains duplicate kid values")
				}
				selected = &key
			}
		}
		if selected == nil {
			return nil, errClientJWKUnknownKid
		}
		return selected, nil
	}

	if len(jwks.Keys) != 1 {
		return nil, errors.New("kid is required unless exactly one key is registered")
	}
	key := jwks.Keys[0]
	if key.Alg != "" && key.Alg != algorithm {
		return nil, errors.New("the sole registered key does not match the assertion algorithm")
	}
	return &key, nil
}

func (r *clientJWKSResolver) fetch(clientID, rawURL string, force bool) (*internalcrypto.JWKS, error) {
	now := r.now()
	r.mu.Lock()
	cached, hasCached := r.cache[rawURL]
	if !force && hasCached && now.Sub(cached.fetchedAt) < clientJWKSCacheTTL {
		r.mu.Unlock()
		copy := cached.jwks
		return &copy, nil
	}
	if active, exists := r.inflight[rawURL]; exists {
		r.mu.Unlock()
		<-active.done
		if active.err != nil {
			return nil, active.err
		}
		copy := *active.jwks
		return &copy, nil
	}
	if force {
		if last, exists := r.lastRefetch[clientID]; exists && now.Sub(last) < clientJWKSRefetchInterval {
			r.mu.Unlock()
			if hasCached {
				copy := cached.jwks
				return &copy, nil
			}
			return nil, errors.New("JWKS refetch is rate limited")
		}
		r.lastRefetch[clientID] = now
	}
	call := &clientJWKSFetchCall{done: make(chan struct{})}
	r.inflight[rawURL] = call
	r.mu.Unlock()

	jwks, fetchErr := r.fetchRemote(rawURL)

	r.mu.Lock()
	if fetchErr == nil {
		r.cache[rawURL] = cachedClientJWKS{jwks: *jwks, fetchedAt: now}
		copy := *jwks
		call.jwks = &copy
	}
	call.err = fetchErr
	delete(r.inflight, rawURL)
	close(call.done)
	r.mu.Unlock()
	if fetchErr != nil {
		return nil, fetchErr
	}
	copy := *jwks
	return &copy, nil
}

func (r *clientJWKSResolver) fetchRemote(rawURL string) (*internalcrypto.JWKS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.fetchTimeout)
	defer cancel()
	if err := r.validateRemoteURL(ctx, rawURL); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := r.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", response.StatusCode)
	}

	limited := io.LimitReader(response.Body, maxClientJWKSResponseSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}
	if len(body) > maxClientJWKSResponseSize {
		return nil, errors.New("JWKS response exceeds 64KB")
	}

	privateMembers, err := internalcrypto.PrivateJWKMembers(body)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS response: %w", err)
	}
	if len(privateMembers) != 0 {
		return nil, errors.New("remote JWKS contains private key material")
	}
	var jwks internalcrypto.JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS response: %w", err)
	}
	usable := make([]internalcrypto.JWK, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		algorithm := ""
		switch {
		case key.Kty == "RSA" && (key.Alg == "" || key.Alg == "RS256"):
			algorithm = "RS256"
		case key.Kty == "EC" && key.Crv == "P-256" && (key.Alg == "" || key.Alg == "ES256"):
			algorithm = "ES256"
		case key.Kty == "OKP" && key.Crv == "Ed25519" && (key.Alg == "" || key.Alg == "EdDSA"):
			algorithm = "EdDSA"
		default:
			continue
		}
		if err := validateClientAssertionKeyBinding(key, algorithm); err != nil {
			continue
		}
		usable = append(usable, key)
	}
	if len(usable) == 0 {
		return nil, errors.New("remote JWKS contains no usable client assertion verification keys")
	}
	return &internalcrypto.JWKS{Keys: usable}, nil
}

func (r *clientJWKSResolver) validateRemoteURL(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid jwks_uri: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("jwks_uri must use https")
	}
	if parsed.User != nil || parsed.Hostname() == "" || parsed.Fragment != "" ||
		strings.Contains(parsed.Hostname(), "%") {
		return errors.New("jwks_uri must not contain userinfo and must have a host")
	}
	ips, err := r.lookupIPs(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("resolve jwks_uri: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("jwks_uri host resolved to no addresses")
	}
	for _, ip := range ips {
		if isBlockedJWKSAddress(ip) {
			return fmt.Errorf("jwks_uri resolves to blocked address %s", ip)
		}
	}
	return nil
}

func (r *clientJWKSResolver) secureDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := r.lookupIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if isBlockedJWKSAddress(ip) {
			lastErr = fmt.Errorf("refusing blocked JWKS address %s", ip)
			continue
		}
		connection, dialErr := r.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("JWKS host resolved to no usable addresses")
	}
	return nil, lastErr
}

var blockedJWKSAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isBlockedJWKSAddress(ip net.IP) bool {
	address, valid := netip.AddrFromSlice(ip)
	if !valid {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range blockedJWKSAddressPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (p *Plugin) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	localPath := "/oauth2/.well-known/oauth-authorization-server"
	canonicalPath := "/.well-known/oauth-authorization-server/oauth2"
	if r.URL.Path != localPath && r.URL.Path != canonicalPath &&
		r.URL.Path != "/.well-known/oauth-authorization-server" {
		http.NotFound(w, r)
		return
	}

	issuer, err := authorizationServerMetadataIssuer(p.baseURL)
	if err != nil {
		writeOAuth2ErrorStatus(w, http.StatusServiceUnavailable, "server_error", "Authorization server metadata requires a valid HTTPS issuer", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              strings.TrimRight(p.baseURL, "/") + "/api/.well-known/jwks.json",
		"scopes_supported":                      []string{"profile", "email", "api:read", "api:write", "ssf.read", "ssf.manage"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "ES256", "EdDSA"},
		"revocation_endpoint":                              issuer + "/revoke",
		"introspection_endpoint":                           issuer + "/introspect",
		"code_challenge_methods_supported":                 []string{"S256"},
		// RFC 9207 Section 3 / FAPI 2.0 SP §5.3.2.2: advertise and return iss
		// on authorization responses.
		"authorization_response_iss_parameter_supported": true,
		// RFC 9449 Section 5.1: signals DPoP support and the acceptable
		// proof JWS algorithms. DPoP itself is opt-in per request (no
		// separate on/off switch to reflect here); this only advertises
		// which algorithms a proof may use.
		"dpop_signing_alg_values_supported": dpop.AllowedAlgorithmsList,
	})
}

func authorizationServerMetadataIssuer(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("RFC 8414 issuer must be derived from a pathless HTTPS origin")
	}
	return strings.TrimRight(baseURL, "/") + "/oauth2", nil
}

func (p *Plugin) handleRegisterPrivateKeyJWTClientJWKS(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if p.lookingGlass == nil {
		writeOAuth2ErrorStatus(w, http.StatusServiceUnavailable, "server_error", "Looking Glass is unavailable", "")
		return
	}
	ownerToken := r.Header.Get(lookingglass.OwnerTokenHeader)
	session, authorized := p.lookingGlass.AuthorizedSessionSnapshot(sessionID, ownerToken)
	if !authorized {
		writeOAuth2ErrorStatus(w, http.StatusUnauthorized, "invalid_client", "Looking Glass session owner capability required", "")
		return
	}
	if session.State != lookingglass.SessionStateActive ||
		session.ProtocolID != "oauth2" ||
		(session.FlowID != "client_credentials" && session.FlowID != "client-credentials") {
		writeOAuth2ErrorStatus(w, http.StatusForbidden, "invalid_request", "An active OAuth2 client_credentials Looking Glass session is required", "")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeOAuth2Error(w, "invalid_request", "JWKS registration requires application/json", "")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxClientJWKSResponseSize+1))
	if err != nil {
		writeOAuth2Error(w, "invalid_request", "Unable to read JWKS registration", "")
		return
	}
	if len(body) > maxClientJWKSResponseSize {
		writeOAuth2Error(w, "invalid_request", "JWKS registration exceeds 64KB", "")
		return
	}

	privateMembers, err := internalcrypto.PrivateJWKMembers(body)
	if err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid JWKS registration", "")
		return
	}
	if len(privateMembers) != 0 {
		writeOAuth2Error(w, "invalid_request", "JWKS registration must not contain private key material", "")
		return
	}
	var jwks internalcrypto.JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid JWKS registration", "")
		return
	}
	if len(jwks.Keys) == 0 || len(jwks.Keys) > 10 {
		writeOAuth2Error(w, "invalid_request", "JWKS registration must contain between 1 and 10 public keys", "")
		return
	}
	for _, key := range jwks.Keys {
		if internalcrypto.JWKContainsPrivateMaterial(key) {
			writeOAuth2Error(w, "invalid_request", "JWKS registration must not contain private key material", "")
			return
		}
		if key.Kid == "" {
			writeOAuth2Error(w, "invalid_request", "Every registered key requires a kid", "")
			return
		}
		if err := validateClientAssertionKeyBinding(key, key.Alg); err != nil {
			writeOAuth2Error(w, "invalid_request", "JWKS contains an unsupported verification key", "")
			return
		}
	}
	if p.mockIdP == nil {
		writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "Unable to register client JWKS", "")
		return
	}
	if err := p.lookingGlass.ClaimPrivateKeyJWTRegistration(sessionID, ownerToken); err != nil {
		switch {
		case errors.Is(err, lookingglass.ErrPrivateKeyJWTAlreadyRegistered):
			writeOAuth2ErrorStatus(w, http.StatusConflict, "invalid_request", "A private_key_jwt client is already registered for this session", "")
		case errors.Is(err, lookingglass.ErrSessionNotActive):
			writeOAuth2ErrorStatus(w, http.StatusForbidden, "invalid_request", "An active OAuth2 client_credentials Looking Glass session is required", "")
		default:
			writeOAuth2ErrorStatus(w, http.StatusUnauthorized, "invalid_client", "Looking Glass session owner capability required", "")
		}
		return
	}
	sessionDigest := sha256.Sum256([]byte(sessionID))
	clientID := "machine-client-pkjwt-" + hex.EncodeToString(sessionDigest[:])
	registeredJWKS := internalcrypto.JWKS{Keys: append([]internalcrypto.JWK(nil), jwks.Keys...)}
	registeredAt := p.now()
	expiresAt := registeredAt.Add(demoClientRegistrationTTL)
	p.mockIdP.RegisterClient(&models.Client{
		ID:                      clientID,
		Name:                    "Looking Glass private_key_jwt client",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"api:read", "api:write"},
		Public:                  false,
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &registeredJWKS,
		CreatedAt:               registeredAt,
		ExpiresAt:               &expiresAt,
	})

	p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "Client Public Key Registered", map[string]interface{}{
		"step":       1,
		"from":       "Client",
		"to":         "Authorization Server",
		"client_id":  clientID,
		"key_count":  len(jwks.Keys),
		"key_ids":    clientJWKKeyIDs(jwks),
		"algorithms": clientJWKAlgorithms(jwks),
		"expires_at": expiresAt,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeRFCReference,
		Title:       "Client JWK Set Registration",
		Description: "Only the client's public verification key is registered; the private key remains client-held.",
		Reference:   "RFC 7517 Section 5",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client_id":      clientID,
		"token_endpoint": strings.TrimRight(p.baseURL, "/") + "/oauth2/token",
		"expires_at":     expiresAt,
		"jwks":           jwks,
	})
}

func clientJWKKeyIDs(jwks internalcrypto.JWKS) []string {
	result := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		result = append(result, key.Kid)
	}
	return result
}

func clientJWKAlgorithms(jwks internalcrypto.JWKS) []string {
	result := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		result = append(result, key.Alg)
	}
	return result
}
