package mockidp

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

func TestSSFStreamClientIsSeeded(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	client, exists := idp.GetClient(SSFStreamClientID)
	if !exists || client == nil {
		t.Fatal("ssf-stream-client was not seeded")
	}
	if client.Public || client.Secret == "" {
		t.Fatal("ssf-stream-client must be a confidential client with a secret")
	}
	hasRead, hasManage := false, false
	for _, scope := range client.Scopes {
		switch scope {
		case "ssf.read":
			hasRead = true
		case "ssf.manage":
			hasManage = true
		}
	}
	if !hasRead || !hasManage {
		t.Fatalf("ssf-stream-client scopes = %v, want ssf.read and ssf.manage", client.Scopes)
	}
	found := false
	for _, preset := range idp.GetDemoClientPresets() {
		if preset.ID == SSFStreamClientID {
			found = true
			if preset.Secret == "" {
				t.Fatal("ssf-stream-client demo preset omitted the secret")
			}
		}
	}
	if !found {
		t.Fatal("ssf-stream-client missing from demo client presets")
	}
}

func TestPrivateKeyJWTClientExistsOnlyAfterSessionRegistration(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	if _, exists := idp.GetClient("machine-client-pkjwt"); exists {
		t.Fatal("unusable private_key_jwt client was seeded")
	}
	for _, preset := range idp.GetDemoClientPresets() {
		if preset.ID == "machine-client-pkjwt" {
			t.Fatal("unusable private_key_jwt preset was exposed")
		}
	}
}

func TestPairwiseSubjectIsDeterministicAndSectorBound(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	idp.SetPairwiseSubjectSalt("test-stable-pairwise-salt")

	first := &models.Client{
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://first.example/callback"},
	}
	second := &models.Client{
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://second.example/callback"},
	}
	firstSubject, err := idp.SubjectForClient(first, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient first: %v", err)
	}
	repeatedSubject, err := idp.SubjectForClient(first, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient repeated: %v", err)
	}
	secondSubject, err := idp.SubjectForClient(second, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient second: %v", err)
	}
	if firstSubject != repeatedSubject {
		t.Fatal("pairwise subject changed for the same user and sector")
	}
	if firstSubject == secondSubject {
		t.Fatal("pairwise subjects matched across distinct sectors")
	}
}

func TestAuthorizationCodeLifetimeIsAtMostSixtySeconds(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	idp.RegisterClient(&models.Client{
		ID:           "code-ttl-client",
		Public:       true,
		RedirectURIs: []string{"https://client.example/callback"},
		GrantTypes:   []string{"authorization_code"},
	})

	before := time.Now()
	authCode, err := idp.CreateAuthorizationCode(
		"code-ttl-client", "alice", "https://client.example/callback",
		"openid", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	after := time.Now()

	if authCode.ExpiresAt.After(before.Add(AuthorizationCodeTTL + time.Second)) {
		t.Fatalf("ExpiresAt = %s exceeds AuthorizationCodeTTL from %s", authCode.ExpiresAt, before)
	}
	if authCode.ExpiresAt.Before(after.Add(AuthorizationCodeTTL - 2*time.Second)) {
		t.Fatalf("ExpiresAt = %s is shorter than expected from %s", authCode.ExpiresAt, after)
	}
	if AuthorizationCodeTTL > 60*time.Second {
		t.Fatalf("AuthorizationCodeTTL = %s, FAPI2 SP Final §5.3.2.1-11 caps at 60s", AuthorizationCodeTTL)
	}
}

func TestValidateAuthorizationCodeRejectsExpiredCode(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	const clientID = "expired-code-client"
	const redirectURI = "https://client.example/callback"
	idp.RegisterClient(&models.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
	})

	authCode, err := idp.CreateAuthorizationCode(
		clientID, "alice", redirectURI, "openid", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	// FAPI2 waits 62s; simulate expiry without sleeping.
	authCode.ExpiresAt = time.Now().Add(-time.Second)

	_, err = idp.ValidateAuthorizationCode(authCode.Code, clientID, redirectURI, "")
	if err == nil || err.Error() != "authorization code expired" {
		t.Fatalf("ValidateAuthorizationCode = %v, want authorization code expired", err)
	}
}

func TestPeekDeviceAuthorizationByUserCodeDoesNotCountFailure(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	now := time.Now()
	auth, err := idp.CreateDeviceAuthorization("public-app", "profile email", "sess", now)
	if err != nil {
		t.Fatal(err)
	}

	peek := idp.PeekDeviceAuthorizationByUserCode(auth.UserCode)
	if peek == nil || peek.UserCode != auth.UserCode || peek.FailedAttempts != 0 {
		t.Fatalf("peek pending = %#v", peek)
	}
	if idp.PeekDeviceAuthorizationByUserCode("ZZZZ-ZZZZ") != nil {
		t.Fatal("unknown user_code must not peek")
	}
	if _, found := idp.LookupDeviceAuthorizationByUserCode(auth.UserCode, now); !found {
		t.Fatal("pending user_code should still look up after peek")
	}
}

// TestValidateClientComparesTheWholeSecret covers the client password check
// (RFC 6749 Section 2.3.1): only the exact secret authenticates a
// confidential client, and a public client is returned as an unauthenticated
// registration that a caller must refuse wherever authentication is needed.
func TestValidateClientComparesTheWholeSecret(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	machine, ok := idp.GetClient("machine-client")
	if !ok || machine.Secret == "" {
		t.Fatal("the seeded machine-client and its secret are required")
	}

	if client, err := idp.ValidateClient("machine-client", machine.Secret); err != nil || client.ID != "machine-client" {
		t.Fatalf("the right secret: client = %v, err = %v", client, err)
	}
	for name, secret := range map[string]string{
		"an empty secret":          "",
		"a prefix of the secret":   machine.Secret[:len(machine.Secret)-1],
		"the secret with a suffix": machine.Secret + "x",
		"another client's secret":  "wrong-secret",
	} {
		if _, err := idp.ValidateClient("machine-client", secret); err == nil {
			t.Fatalf("%s authenticated machine-client", name)
		}
	}
	if _, err := idp.ValidateClient("no-such-client", machine.Secret); err == nil {
		t.Fatal("an unknown client was validated")
	}

	public, err := idp.ValidateClient("public-app", "anything")
	if err != nil || !public.Public {
		t.Fatalf("public-app: client = %v, err = %v, want the public registration", public, err)
	}

	alice, ok := idp.GetUserByEmail("alice@example.com")
	if !ok || alice.Password == "" {
		t.Fatal("the seeded End-User alice and her password are required")
	}
	if _, err := idp.ValidateCredentials(alice.Email, alice.Password); err != nil {
		t.Fatalf("the right End-User password: %v", err)
	}
	if _, err := idp.ValidateCredentials(alice.Email, alice.Password[:len(alice.Password)-1]); err == nil {
		t.Fatal("a prefix of the End-User password was accepted")
	}
}

// TestRevokeRefreshTokenInvalidatesTheGrantsAccessTokens covers RFC 7009
// Section 2.1: "If the particular token is a refresh token and the
// authorization server supports the revocation of access tokens, then the
// authorization server SHOULD also invalidate all access tokens based on the
// same authorization grant". The grant's access tokens follow the refresh
// token through rotation, and another grant's tokens are untouched.
func TestRevokeRefreshTokenInvalidatesTheGrantsAccessTokens(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	mint := func(lifetime time.Duration) (token, jti string) {
		t.Helper()
		token, err := idp.JWTService().CreateAccessToken(crypto.AccessToken{
			Issuer: "https://as.example", Subject: "alice", Audience: "https://rs.example",
			ClientID: "public-app", Scope: "profile", Lifetime: lifetime,
		})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := idp.JWTService().ValidateToken(token)
		if err != nil {
			t.Fatal(err)
		}
		jti, _ = claims["jti"].(string)
		if jti == "" {
			t.Fatal("the access token has no jti")
		}
		return token, jti
	}
	store := func(refreshToken string) {
		idp.StoreRefreshToken(refreshToken, "public-app", "alice", "profile", time.Now(), time.Now().Add(time.Hour))
	}

	// One grant: a first access token, then a rotation with a second one.
	store("refresh-1")
	first, firstJTI := mint(time.Hour)
	idp.RecordGrantTokens(first, "refresh-1", nil)
	rotatedOut, err := idp.ValidateRefreshToken("refresh-1", "public-app")
	if err != nil {
		t.Fatal(err)
	}
	store("refresh-2")
	second, secondJTI := mint(time.Hour)
	idp.RecordGrantTokens(second, "refresh-2", rotatedOut)
	// An access token of the grant that expires before the revocation.
	shortLived, _ := mint(time.Second)
	idp.RecordGrantTokens(shortLived, "refresh-2", nil)
	// Another grant of the same client and user.
	store("refresh-other")
	other, _ := mint(time.Hour)
	idp.RecordGrantTokens(other, "refresh-other", nil)

	time.Sleep(1100 * time.Millisecond)
	invalidated := idp.RevokeRefreshToken("refresh-2")
	if want := []string{firstJTI, secondJTI}; !reflect.DeepEqual(invalidated, want) {
		t.Fatalf("invalidated = %q, want the grant's two unexpired access tokens %q", invalidated, want)
	}
	if !idp.IsTokenRevoked(first) || !idp.IsTokenRevoked(second) {
		t.Fatal("an access token of the revoked grant is still usable")
	}
	if _, live := idp.GetRefreshToken("refresh-2"); live {
		t.Fatal("the refresh token is still usable")
	}
	if idp.IsTokenRevoked(other) {
		t.Fatal("an access token of another grant was revoked")
	}
	if _, live := idp.GetRefreshToken("refresh-other"); !live {
		t.Fatal("the refresh token of another grant was revoked")
	}
	for _, gone := range []string{"refresh-2", "refresh-1", "never-issued"} {
		if again := idp.RevokeRefreshToken(gone); again != nil {
			t.Fatalf("revoking %s, which is not a live refresh token, invalidated %q", gone, again)
		}
	}
}

// TestAuthorizationCodeReplayRevokesRefreshedTokens covers RFC 6749 Section
// 4.1.2: "If an authorization code is used more than once, the authorization
// server MUST deny the request and SHOULD revoke (when possible) all tokens
// previously issued based on that authorization code." The tokens obtained by
// refreshing are based on that code too, and the replay is still recognised
// after usedCodeRetention while the grant has a live refresh token.
func TestAuthorizationCodeReplayRevokesRefreshedTokens(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	mint := func() (token, jti string) {
		t.Helper()
		token, err := idp.JWTService().CreateAccessToken(crypto.AccessToken{
			Issuer: "https://as.example", Subject: "alice", Audience: "https://rs.example",
			ClientID: "public-app", Scope: "profile", Lifetime: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := idp.JWTService().ValidateToken(token)
		if err != nil {
			t.Fatal(err)
		}
		jti, _ = claims["jti"].(string)
		return token, jti
	}
	const redirectURI = "http://localhost:3000/callback"
	redeem := func(refreshToken string) (code, accessToken, jti string) {
		t.Helper()
		authCode, err := idp.CreateAuthorizationCode("public-app", "alice", redirectURI, "profile", "", "", "", "", "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := idp.ValidateAuthorizationCode(authCode.Code, "public-app", redirectURI, ""); err != nil {
			t.Fatal(err)
		}
		accessToken, jti = mint()
		idp.StoreRefreshToken(refreshToken, "public-app", "alice", "profile", time.Now(), time.Now().Add(time.Hour))
		idp.RecordIssuedTokens(authCode.Code, accessToken, refreshToken)
		idp.RecordGrantTokens(accessToken, refreshToken, nil)
		return authCode.Code, accessToken, jti
	}

	// One grant, refreshed once; another grant from another code.
	code, first, firstJTI := redeem("refresh-1")
	rotatedOut, err := idp.ValidateRefreshToken("refresh-1", "public-app")
	if err != nil {
		t.Fatal(err)
	}
	idp.StoreRefreshToken("refresh-2", "public-app", "alice", "profile", time.Now(), time.Now().Add(time.Hour))
	second, secondJTI := mint()
	idp.RecordGrantTokens(second, "refresh-2", rotatedOut)
	_, other, _ := redeem("refresh-other")

	// The record outlives usedCodeRetention because the grant can still be
	// refreshed; a code whose grant has no refresh token left is forgotten.
	idp.mu.Lock()
	idp.usedCodes[code].usedAt = time.Now().Add(-2 * usedCodeRetention)
	idp.usedCodes["spent-long-ago"] = &usedAuthorizationCode{usedAt: time.Now().Add(-2 * usedCodeRetention)}
	idp.mu.Unlock()

	_, err = idp.ValidateAuthorizationCode(code, "public-app", redirectURI, "")
	var replay *AuthorizationCodeReplay
	if !errors.As(err, &replay) {
		t.Fatalf("replay error = %v, want an AuthorizationCodeReplay", err)
	}
	if err.Error() != "authorization code already used" {
		t.Fatalf("replay error = %q", err.Error())
	}
	if want := []string{firstJTI, secondJTI}; !reflect.DeepEqual(replay.AccessTokenJTIs, want) || replay.RefreshTokens != 1 {
		t.Fatalf("replay revoked access tokens %q and %d refresh tokens, want %q and 1", replay.AccessTokenJTIs, replay.RefreshTokens, want)
	}
	if !idp.IsTokenRevoked(first) || !idp.IsTokenRevoked(second) {
		t.Fatal("an access token issued from the replayed code is still usable")
	}
	if _, live := idp.GetRefreshToken("refresh-2"); live {
		t.Fatal("the rotated refresh token of the replayed code is still usable")
	}
	if idp.IsTokenRevoked(other) {
		t.Fatal("an access token of another code was revoked")
	}
	if _, live := idp.GetRefreshToken("refresh-other"); !live {
		t.Fatal("the refresh token of another code was revoked")
	}
	idp.mu.RLock()
	_, kept := idp.usedCodes["spent-long-ago"]
	idp.mu.RUnlock()
	if kept {
		t.Fatal("a code with no refresh token left was remembered past usedCodeRetention")
	}

	// A second replay is still denied. Nothing is left to revoke, so the old
	// record is no longer kept and the code is simply unknown.
	if _, err = idp.ValidateAuthorizationCode(code, "public-app", redirectURI, ""); err == nil {
		t.Fatal("a second replay of the code was accepted")
	}
}

// The authorization servers support the S256 code challenge method only
// (RFC 7636 Section 4.4.1). A code_challenge sent without a method asks for
// plain, by Section 4.3.
func TestPKCEVerifiesS256AndNothingElse(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // RFC 7636 Appendix B

	if err := ValidatePKCEWithError(verifier, challenge, PKCEMethodS256); err != nil {
		t.Fatalf("S256 with the Appendix B values: %v", err)
	}
	for name, method := range map[string]string{"plain": "plain", "absent": ""} {
		// With plain the challenge is the verifier itself.
		err := ValidatePKCEWithError(verifier, verifier, method)
		var pkceErr *PKCEError
		if !errors.As(err, &pkceErr) || pkceErr.Code != "invalid_request" {
			t.Errorf("%s: err = %v, want invalid_request", name, err)
		}
		if PKCEMethodError(method) == "" {
			t.Errorf("%s: the authorization endpoint must have a reason to refuse it", name)
		}
	}
	if PKCEMethodError(PKCEMethodS256) != "" {
		t.Error("S256 is supported")
	}
}
