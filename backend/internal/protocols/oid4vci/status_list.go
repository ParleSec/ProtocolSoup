package oid4vci

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const (
	haipStatusListID       = "haip-sd-jwt-1"
	haipStatusListBitCount = 1 << 20
)

func (p *Plugin) allocateStatusListIndex() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.statusListIndexes == nil {
		p.statusListIndexes = make(map[int]struct{})
	}
	for attempts := 0; attempts < 128; attempts++ {
		random := make([]byte, 3)
		if _, err := rand.Read(random); err != nil {
			return 0, fmt.Errorf("generate status list index: %w", err)
		}
		index := int(random[0])<<16 | int(random[1])<<8 | int(random[2])
		index %= haipStatusListBitCount
		if _, used := p.statusListIndexes[index]; used {
			continue
		}
		p.statusListIndexes[index] = struct{}{}
		return index, nil
	}
	return 0, fmt.Errorf("unable to allocate a unique status list index")
}

func (p *Plugin) statusListURI() string {
	return p.issuerID() + "/status-lists/" + haipStatusListID
}

func (p *Plugin) handleStatusList(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "listID") != haipStatusListID {
		http.NotFound(w, r)
		return
	}
	token, err := p.signStatusListToken()
	if err != nil {
		writeServerError(w, "sign status list token", err)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

func (p *Plugin) signStatusListToken() (string, error) {
	if p.mdocPKI == nil || p.mdocPKI.DocumentSignerKey() == nil {
		return "", fmt.Errorf("certificate-backed status list signer is unavailable")
	}
	// Every allocated entry is initially valid, so the bitstring is all zeroes.
	// Allocated indices are nevertheless tracked uniquely to avoid credential
	// correlation and permit future revocation updates without reissuing IDs.
	bits := make([]byte, haipStatusListBitCount/8)
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(bits); err != nil {
		return "", fmt.Errorf("compress status list: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("close status list compressor: %w", err)
	}
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": p.issuerID(),
		"sub": p.statusListURI(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"status_list": map[string]interface{}{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString(compressed.Bytes()),
		},
	})
	token.Header["typ"] = "statuslist+jwt"
	chain := p.mdocPKI.DocumentSignerChain()
	if len(chain) == 0 {
		return "", fmt.Errorf("certificate-backed status list signer chain is unavailable")
	}
	x5c := make([]string, 0, len(chain))
	for _, certificate := range chain {
		if certificate == nil {
			return "", fmt.Errorf("certificate-backed status list signer chain contains an empty certificate")
		}
		x5c = append(x5c, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	token.Header["x5c"] = x5c
	return token.SignedString(p.mdocPKI.DocumentSignerKey())
}
