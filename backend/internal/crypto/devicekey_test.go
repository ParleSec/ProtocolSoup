package crypto

import (
	"crypto/elliptic"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateDeviceKeyPersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "device_key.pem")

	first, err := LoadOrCreateDeviceKey(path)
	if err != nil {
		t.Fatalf("first LoadOrCreateDeviceKey: %v", err)
	}
	if first.Curve != elliptic.P256() {
		t.Fatalf("device key curve = %v, want P-256", first.Curve)
	}

	// A second load must return the SAME key. Regenerating it would silently
	// invalidate the device binding of every stored credential.
	second, err := LoadOrCreateDeviceKey(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateDeviceKey: %v", err)
	}
	if !first.PublicKey.Equal(&second.PublicKey) {
		t.Fatal("device key changed across reload; persistence is broken")
	}
	if first.D.Cmp(second.D) != 0 {
		t.Fatal("device private scalar changed across reload")
	}
}

func TestLoadOrCreateDeviceKeyEphemeralWhenPathEmpty(t *testing.T) {
	a, err := LoadOrCreateDeviceKey("")
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceKey(\"\"): %v", err)
	}
	b, err := LoadOrCreateDeviceKey("")
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceKey(\"\") second: %v", err)
	}
	if a.PublicKey.Equal(&b.PublicKey) {
		t.Fatal("ephemeral device keys must differ between calls")
	}
}
