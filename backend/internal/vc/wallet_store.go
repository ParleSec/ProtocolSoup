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
	VCT                       string     `json:"vct,omitempty"`
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

// WalletCredentialStore keeps wallet credential records by subject and credential key.
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
	credential := strings.TrimSpace(record.CredentialJWT)
	format := strings.TrimSpace(record.Format)
	configID := strings.TrimSpace(record.CredentialConfigurationID)
	vct := strings.TrimSpace(record.VCT)
	doctype := strings.TrimSpace(record.Doctype)
	if subject == "" || credential == "" {
		return false
	}
	if format == "" && configID == "" && vct == "" && doctype == "" {
		return false
	}

	now := time.Now().UTC()
	record.Subject = subject
	record.Format = format
	record.CredentialConfigurationID = configID
	record.VCT = vct
	record.Doctype = doctype
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
	key := walletRecordStoreKey(record)
	if existing, ok := s.credentials[subject][key]; ok && !existing.IssuedAt.IsZero() {
		record.IssuedAt = existing.IssuedAt
	}
	s.credentials[subject][key] = record
	if err := s.persistLocked(); err != nil {
		return false
	}
	return true
}

// Get returns the most recently updated credential record for a subject and VCT.
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
	var (
		matched WalletCredentialRecord
		found   bool
	)
	for _, record := range byVCT {
		if strings.TrimSpace(record.VCT) != normalizedVCT {
			continue
		}
		if !found || record.UpdatedAt.After(matched.UpdatedAt) {
			matched = record
			found = true
		}
	}
	return matched, found
}

// FindByID returns a credential record for a subject by credential_id.
func (s *WalletCredentialStore) FindByID(subject, credentialID string) (WalletCredentialRecord, bool) {
	if s == nil {
		return WalletCredentialRecord{}, false
	}
	normalizedSubject := strings.TrimSpace(subject)
	normalizedCredentialID := strings.TrimSpace(credentialID)
	if normalizedSubject == "" || normalizedCredentialID == "" {
		return WalletCredentialRecord{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncFromDiskLocked(); err != nil {
		return WalletCredentialRecord{}, false
	}
	recordsByKey, ok := s.credentials[normalizedSubject]
	if !ok {
		return WalletCredentialRecord{}, false
	}
	for _, record := range recordsByKey {
		if strings.TrimSpace(record.CredentialID) == normalizedCredentialID {
			return record, true
		}
	}
	return WalletCredentialRecord{}, false
}

// FindByConfiguration returns the most recently updated record for a subject and credential_configuration_id.
func (s *WalletCredentialStore) FindByConfiguration(subject, configurationID string) (WalletCredentialRecord, bool) {
	if s == nil {
		return WalletCredentialRecord{}, false
	}
	normalizedSubject := strings.TrimSpace(subject)
	normalizedConfigurationID := strings.TrimSpace(configurationID)
	if normalizedSubject == "" || normalizedConfigurationID == "" {
		return WalletCredentialRecord{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncFromDiskLocked(); err != nil {
		return WalletCredentialRecord{}, false
	}
	recordsByKey, ok := s.credentials[normalizedSubject]
	if !ok {
		return WalletCredentialRecord{}, false
	}
	var (
		matched WalletCredentialRecord
		found   bool
	)
	for _, record := range recordsByKey {
		if strings.TrimSpace(record.CredentialConfigurationID) != normalizedConfigurationID {
			continue
		}
		if !found || record.UpdatedAt.After(matched.UpdatedAt) {
			matched = record
			found = true
		}
	}
	return matched, found
}

// List returns all credential records for a subject ordered by updated_at descending.
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
	recordsByKey, ok := s.credentials[normalizedSubject]
	if !ok || len(recordsByKey) == 0 {
		return nil
	}
	records := make([]WalletCredentialRecord, 0, len(recordsByKey))
	for _, record := range recordsByKey {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			leftID := strings.TrimSpace(records[i].CredentialID)
			rightID := strings.TrimSpace(records[j].CredentialID)
			return leftID < rightID
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	return records
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

func walletRecordStoreKey(record WalletCredentialRecord) string {
	credentialID := strings.TrimSpace(record.CredentialID)
	if credentialID != "" {
		return "credential_id:" + credentialID
	}
	configurationID := strings.TrimSpace(record.CredentialConfigurationID)
	if configurationID != "" {
		return "configuration_id:" + configurationID + "|format:" + strings.TrimSpace(record.Format)
	}
	vct := strings.TrimSpace(record.VCT)
	if vct != "" {
		return "vct:" + vct + "|format:" + strings.TrimSpace(record.Format)
	}
	doctype := strings.TrimSpace(record.Doctype)
	if doctype != "" {
		return "doctype:" + doctype + "|format:" + strings.TrimSpace(record.Format)
	}
	return "credential:" + strings.TrimSpace(record.CredentialJWT)
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
