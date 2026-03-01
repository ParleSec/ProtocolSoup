package vc

import (
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

// WalletCredentialRecord stores a wallet-held credential and trust material.
type WalletCredentialRecord struct {
	Subject       string     `json:"subject"`
	VCT           string     `json:"vct"`
	CredentialJWT string     `json:"credential_jwt"`
	Issuer        string     `json:"issuer"`
	IssuerJWK     crypto.JWK `json:"issuer_jwk"`
	IssuedAt      time.Time  `json:"issued_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// WalletCredentialStore keeps wallet credential records by subject and VCT.
type WalletCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]map[string]WalletCredentialRecord
}

var defaultWalletCredentialStore = NewWalletCredentialStore()

// NewWalletCredentialStore creates an empty credential store.
func NewWalletCredentialStore() *WalletCredentialStore {
	return &WalletCredentialStore{
		credentials: make(map[string]map[string]WalletCredentialRecord),
	}
}

// DefaultWalletCredentialStore returns the process-wide wallet credential store.
func DefaultWalletCredentialStore() *WalletCredentialStore {
	return defaultWalletCredentialStore
}

// Put stores or updates a wallet credential record.
func (s *WalletCredentialStore) Put(record WalletCredentialRecord) bool {
	if s == nil {
		return false
	}
	subject := strings.TrimSpace(record.Subject)
	vct := strings.TrimSpace(record.VCT)
	credential := strings.TrimSpace(record.CredentialJWT)
	if subject == "" || vct == "" || credential == "" {
		return false
	}

	now := time.Now().UTC()
	record.Subject = subject
	record.VCT = vct
	record.CredentialJWT = credential
	if record.IssuedAt.IsZero() {
		record.IssuedAt = now
	}
	record.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[subject]; !ok {
		s.credentials[subject] = make(map[string]WalletCredentialRecord)
	}
	s.credentials[subject][vct] = record
	return true
}

// Get returns a credential record for a subject and VCT.
func (s *WalletCredentialStore) Get(subject, vct string) (WalletCredentialRecord, bool) {
	if s == nil {
		return WalletCredentialRecord{}, false
	}
	normalizedSubject := strings.TrimSpace(subject)
	normalizedVCT := strings.TrimSpace(vct)
	if normalizedSubject == "" || normalizedVCT == "" {
		return WalletCredentialRecord{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	byVCT, ok := s.credentials[normalizedSubject]
	if !ok {
		return WalletCredentialRecord{}, false
	}
	record, ok := byVCT[normalizedVCT]
	return record, ok
}

// Reset clears all records. Intended for test isolation.
func (s *WalletCredentialStore) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.credentials = make(map[string]map[string]WalletCredentialRecord)
	s.mu.Unlock()
}
