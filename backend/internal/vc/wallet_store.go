package vc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

// WalletCredentialRecord stores a wallet-held credential and trust material.
type WalletCredentialRecord struct {
	Subject                   string     `json:"subject"`
	Format                    string     `json:"format,omitempty"`
	CredentialConfigurationID string     `json:"credential_configuration_id,omitempty"`
	VCT                       string     `json:"vct"`
	Doctype                   string     `json:"doctype,omitempty"`
	CredentialTypes           []string   `json:"credential_types,omitempty"`
	CredentialJWT             string     `json:"credential_jwt"`
	IssuerSignedJWT           string     `json:"issuer_signed_jwt,omitempty"`
	CredentialID              string     `json:"credential_id,omitempty"`
	Issuer                    string     `json:"issuer"`
	IssuerJWK                 crypto.JWK `json:"issuer_jwk"`
	IssuedAt                  time.Time  `json:"issued_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

// WalletCredentialStore keeps wallet credential records by subject and VCT.
type WalletCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]map[string]WalletCredentialRecord
	dataPath    string
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

type walletCredentialStoreSnapshot struct {
	Credentials map[string]map[string]WalletCredentialRecord `json:"credentials"`
	UpdatedAt   time.Time                                    `json:"updated_at"`
}

// EnablePersistence configures a durable JSON store path for issuance lineage.
func (s *WalletCredentialStore) EnablePersistence(path string) error {
	if s == nil {
		return nil
	}
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return nil
	}
	normalized = filepath.Clean(normalized)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dataPath == normalized {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(normalized), 0o755); err != nil {
		return err
	}
	s.dataPath = normalized
	return s.syncFromDiskLocked()
}

// DisablePersistence turns off disk synchronization for the store.
func (s *WalletCredentialStore) DisablePersistence() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.dataPath = ""
	s.mu.Unlock()
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
	record.Format = strings.TrimSpace(record.Format)
	record.CredentialConfigurationID = strings.TrimSpace(record.CredentialConfigurationID)
	record.VCT = vct
	record.Doctype = strings.TrimSpace(record.Doctype)
	record.CredentialTypes = normalizeUniqueStringSlice(record.CredentialTypes)
	record.CredentialJWT = credential
	if strings.TrimSpace(record.IssuerSignedJWT) == "" {
		if parsed, err := ParseSDJWTEnvelope(credential); err == nil {
			record.IssuerSignedJWT = strings.TrimSpace(parsed.IssuerSignedJWT)
		}
	}
	if strings.TrimSpace(record.CredentialID) == "" {
		tokenForID := strings.TrimSpace(record.IssuerSignedJWT)
		if tokenForID == "" {
			tokenForID = strings.TrimSpace(record.CredentialJWT)
		}
		if decoded, err := crypto.DecodeTokenWithoutValidation(tokenForID); err == nil {
			if jti, ok := decoded.Payload["jti"].(string); ok {
				record.CredentialID = strings.TrimSpace(jti)
			}
		}
	}
	if record.IssuedAt.IsZero() {
		record.IssuedAt = now
	}
	record.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncFromDiskLocked(); err != nil {
		return false
	}
	if _, ok := s.credentials[subject]; !ok {
		s.credentials[subject] = make(map[string]WalletCredentialRecord)
	}
	s.credentials[subject][vct] = record
	if err := s.persistLocked(); err != nil {
		return false
	}
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

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncFromDiskLocked(); err != nil {
		return WalletCredentialRecord{}, false
	}
	byVCT, ok := s.credentials[normalizedSubject]
	if !ok {
		return WalletCredentialRecord{}, false
	}
	record, ok := byVCT[normalizedVCT]
	return record, ok
}

// List returns all credential records for a subject.
func (s *WalletCredentialStore) List(subject string) []WalletCredentialRecord {
	if s == nil {
		return nil
	}
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncFromDiskLocked(); err != nil {
		return nil
	}
	byVCT, ok := s.credentials[normalizedSubject]
	if !ok {
		return nil
	}
	records := make([]WalletCredentialRecord, 0, len(byVCT))
	for _, record := range byVCT {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	return records
}

// FindByID returns a credential record for a subject and credential ID.
func (s *WalletCredentialStore) FindByID(subject string, credentialID string) (WalletCredentialRecord, bool) {
	normalizedID := strings.TrimSpace(credentialID)
	if normalizedID == "" {
		return WalletCredentialRecord{}, false
	}
	for _, record := range s.List(subject) {
		if strings.TrimSpace(record.CredentialID) == normalizedID {
			return record, true
		}
	}
	return WalletCredentialRecord{}, false
}

// FindByConfiguration returns a record that matches configuration constraints.
func (s *WalletCredentialStore) FindByConfiguration(subject string, configurationID string, format string) (WalletCredentialRecord, bool) {
	normalizedConfigurationID := strings.TrimSpace(configurationID)
	normalizedFormat := strings.TrimSpace(format)
	for _, record := range s.List(subject) {
		if normalizedConfigurationID != "" && strings.TrimSpace(record.CredentialConfigurationID) != normalizedConfigurationID {
			continue
		}
		if normalizedFormat != "" && strings.TrimSpace(record.Format) != normalizedFormat {
			continue
		}
		return record, true
	}
	return WalletCredentialRecord{}, false
}

// Reset clears all records. Intended for test isolation.
func (s *WalletCredentialStore) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.credentials = make(map[string]map[string]WalletCredentialRecord)
	_ = s.persistLocked()
	s.mu.Unlock()
}

func (s *WalletCredentialStore) syncFromDiskLocked() error {
	if s == nil || strings.TrimSpace(s.dataPath) == "" {
		return nil
	}
	snapshot, err := readWalletSnapshot(s.dataPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if snapshot.Credentials == nil {
		s.credentials = make(map[string]map[string]WalletCredentialRecord)
		return nil
	}
	s.credentials = snapshot.Credentials
	return nil
}

func (s *WalletCredentialStore) persistLocked() error {
	if s == nil || strings.TrimSpace(s.dataPath) == "" {
		return nil
	}
	snapshot := walletCredentialStoreSnapshot{
		Credentials: s.credentials,
		UpdatedAt:   time.Now().UTC(),
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tempPath := s.dataPath + ".tmp"
	if err := os.WriteFile(tempPath, serialized, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, s.dataPath)
}

func readWalletSnapshot(path string) (*walletCredentialStoreSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return &walletCredentialStoreSnapshot{
			Credentials: make(map[string]map[string]WalletCredentialRecord),
		}, nil
	}
	var snapshot walletCredentialStoreSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Credentials == nil {
		snapshot.Credentials = make(map[string]map[string]WalletCredentialRecord)
	}
	return &snapshot, nil
}

func normalizeUniqueStringSlice(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}
