package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// keyStoreFile is the on-disk name for the persisted key set.
const keyStoreFile = "keyset.json"

// persistedKeySet is the JSON serialisation of a KeySet's private material,
// key IDs, and retired public keys. Private keys are PEM encoded.
type persistedKeySet struct {
	RSAPrivPEM     string    `json:"rsa_private_pem"`
	ECPrivPEM      string    `json:"ec_private_pem"`
	Ed25519PrivPEM string    `json:"ed25519_private_pem"`
	RSAKeyID       string    `json:"rsa_kid"`
	ECKeyID        string    `json:"ec_kid"`
	Ed25519KeyID   string    `json:"ed25519_kid"`
	CreatedAt      time.Time `json:"created_at"`
	Retired        []JWK     `json:"retired_public_keys,omitempty"`
}

// LoadOrCreateKeySet returns a key set persisted under dir. On first run it
// generates a fresh key set and writes it; on subsequent runs it loads the same
// keys so key IDs and signatures remain stable across restarts. An empty dir
// returns an ephemeral in-memory key set (development only); a certified
// deployment MUST pass a durable directory so issued tokens stay verifiable.
func LoadOrCreateKeySet(dir string) (*KeySet, error) {
	if dir == "" {
		return NewKeySet()
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create key store dir %q: %w", dir, err)
	}

	path := filepath.Join(dir, keyStoreFile)
	if _, err := os.Stat(path); err == nil {
		ks, loadErr := loadKeySet(path)
		if loadErr != nil {
			return nil, fmt.Errorf("failed to load key set from %q: %w", path, loadErr)
		}
		ks.storePath = dir
		return ks, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to stat key store %q: %w", path, err)
	}

	ks, err := NewKeySet()
	if err != nil {
		return nil, err
	}
	ks.storePath = dir

	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := ks.persistLocked(); err != nil {
		return nil, fmt.Errorf("failed to persist new key set to %q: %w", dir, err)
	}
	return ks, nil
}

func loadKeySet(path string) (*KeySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var persisted persistedKeySet
	if err := json.Unmarshal(raw, &persisted); err != nil {
		return nil, fmt.Errorf("invalid key store JSON: %w", err)
	}

	rsaKey, err := parseRSAPrivatePEM(persisted.RSAPrivPEM)
	if err != nil {
		return nil, fmt.Errorf("rsa key: %w", err)
	}
	ecKey, err := parseECPrivatePEM(persisted.ECPrivPEM)
	if err != nil {
		return nil, fmt.Errorf("ec key: %w", err)
	}
	edKey, err := parseEd25519PrivatePEM(persisted.Ed25519PrivPEM)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key: %w", err)
	}

	if persisted.RSAKeyID == "" || persisted.ECKeyID == "" || persisted.Ed25519KeyID == "" {
		return nil, errors.New("key store missing one or more key IDs")
	}

	createdAt := persisted.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	return &KeySet{
		rsaKey:       rsaKey,
		ecKey:        ecKey,
		ed25519Key:   edKey,
		rsaKeyID:     persisted.RSAKeyID,
		ecKeyID:      persisted.ECKeyID,
		ed25519KeyID: persisted.Ed25519KeyID,
		createdAt:    createdAt,
		retired:      persisted.Retired,
	}, nil
}

// persistLocked writes the current key set to its backing store atomically. The
// caller MUST hold ks.mu.
func (ks *KeySet) persistLocked() error {
	if ks.storePath == "" {
		return nil
	}

	rsaPEM, err := encodeRSAPrivatePEM(ks.rsaKey)
	if err != nil {
		return err
	}
	ecPEM, err := encodeECPrivatePEM(ks.ecKey)
	if err != nil {
		return err
	}
	edPEM, err := encodeEd25519PrivatePEM(ks.ed25519Key)
	if err != nil {
		return err
	}

	persisted := persistedKeySet{
		RSAPrivPEM:     rsaPEM,
		ECPrivPEM:      ecPEM,
		Ed25519PrivPEM: edPEM,
		RSAKeyID:       ks.rsaKeyID,
		ECKeyID:        ks.ecKeyID,
		Ed25519KeyID:   ks.ed25519KeyID,
		CreatedAt:      ks.createdAt,
		Retired:        ks.retired,
	}

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(ks.storePath, keyStoreFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func encodeRSAPrivatePEM(key *rsa.PrivateKey) (string, error) {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parseRSAPrivatePEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func encodeECPrivatePEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parseECPrivatePEM(s string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func encodeEd25519PrivatePEM(key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parseEd25519PrivatePEM(s string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %T", parsed)
	}
	return key, nil
}
