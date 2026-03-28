package vc

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"golang.org/x/crypto/pbkdf2"
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
	secret      string
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

type encryptedWalletCredentialStoreSnapshot struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"alg"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const (
	walletStoreEncryptionVersion    = 1
	walletStoreEncryptionAlgorithm  = "AES-256-GCM"
	walletStoreEncryptionKDF        = "PBKDF2-SHA256"
	walletStorePBKDF2Iterations     = 210000
	walletStorePBKDF2DerivedKeySize = 32
)

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

// SetEncryptionKey configures an optional passphrase for encrypting persisted snapshots.
func (s *WalletCredentialStore) SetEncryptionKey(secret string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.secret = strings.TrimSpace(secret)
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
	snapshot, err := readWalletSnapshot(s.dataPath, s.secret)
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
	serialized, err := marshalWalletSnapshot(snapshot, s.secret)
	if err != nil {
		return err
	}
	tempPath := s.dataPath + ".tmp"
	if err := os.WriteFile(tempPath, serialized, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, s.dataPath)
}

func readWalletSnapshot(path string, secret string) (*walletCredentialStoreSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return &walletCredentialStoreSnapshot{
			Credentials: make(map[string]map[string]WalletCredentialRecord),
		}, nil
	}
	snapshot, err := unmarshalWalletSnapshot(raw, secret)
	if err != nil {
		return nil, err
	}
	if snapshot.Credentials == nil {
		snapshot.Credentials = make(map[string]map[string]WalletCredentialRecord)
	}
	return snapshot, nil
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

func marshalWalletSnapshot(snapshot walletCredentialStoreSnapshot, secret string) ([]byte, error) {
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(secret) == "" {
		return serialized, nil
	}

	salt := make([]byte, 16)
	if _, err := cryptorand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(secret), salt, walletStorePBKDF2Iterations, walletStorePBKDF2DerivedKeySize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, serialized, nil)
	envelope := encryptedWalletCredentialStoreSnapshot{
		Version:    walletStoreEncryptionVersion,
		Algorithm:  walletStoreEncryptionAlgorithm,
		KDF:        walletStoreEncryptionKDF,
		Iterations: walletStorePBKDF2Iterations,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(envelope)
}

func unmarshalWalletSnapshot(raw []byte, secret string) (*walletCredentialStoreSnapshot, error) {
	var encryptedEnvelope encryptedWalletCredentialStoreSnapshot
	if err := json.Unmarshal(raw, &encryptedEnvelope); err == nil &&
		strings.TrimSpace(encryptedEnvelope.Ciphertext) != "" &&
		strings.TrimSpace(encryptedEnvelope.Nonce) != "" {
		if strings.TrimSpace(secret) == "" {
			return nil, fmt.Errorf("wallet snapshot is encrypted and requires WALLET_PERSISTENCE_KEY")
		}
		if encryptedEnvelope.Algorithm != "" && encryptedEnvelope.Algorithm != walletStoreEncryptionAlgorithm {
			return nil, fmt.Errorf("unsupported wallet snapshot algorithm %q", encryptedEnvelope.Algorithm)
		}
		if encryptedEnvelope.KDF != "" && encryptedEnvelope.KDF != walletStoreEncryptionKDF {
			return nil, fmt.Errorf("unsupported wallet snapshot kdf %q", encryptedEnvelope.KDF)
		}
		if encryptedEnvelope.Iterations <= 0 {
			encryptedEnvelope.Iterations = walletStorePBKDF2Iterations
		}
		salt, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encryptedEnvelope.Salt))
		if err != nil {
			return nil, fmt.Errorf("decode wallet snapshot salt: %w", err)
		}
		nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encryptedEnvelope.Nonce))
		if err != nil {
			return nil, fmt.Errorf("decode wallet snapshot nonce: %w", err)
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encryptedEnvelope.Ciphertext))
		if err != nil {
			return nil, fmt.Errorf("decode wallet snapshot ciphertext: %w", err)
		}
		key := pbkdf2.Key([]byte(secret), salt, encryptedEnvelope.Iterations, walletStorePBKDF2DerivedKeySize, sha256.New)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt wallet snapshot: %w", err)
		}
		var snapshot walletCredentialStoreSnapshot
		if err := json.Unmarshal(plaintext, &snapshot); err != nil {
			return nil, err
		}
		return &snapshot, nil
	}

	var snapshot walletCredentialStoreSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}
