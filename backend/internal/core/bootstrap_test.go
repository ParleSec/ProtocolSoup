package core

import (
	"testing"
)

func TestProductionBaseURLRequiresHTTPSIssuer(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{name: "HTTPS issuer", baseURL: "https://as.example", wantErr: false},
		{name: "HTTP issuer", baseURL: "http://as.example", wantErr: true},
		{name: "path", baseURL: "https://as.example/base", wantErr: true},
		{name: "trailing slash", baseURL: "https://as.example/", wantErr: true},
		{name: "query", baseURL: "https://as.example?tenant=one", wantErr: true},
		{name: "fragment", baseURL: "https://as.example#issuer", wantErr: true},
		{name: "missing host", baseURL: "https:///oauth2", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProductionBaseURL(&Config{
				Environment: "production",
				BaseURL:     test.baseURL,
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("validateProductionBaseURL() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
	if err := validateProductionBaseURL(&Config{
		Environment: "development",
		BaseURL:     "http://127.0.0.1:8080",
	}); err != nil {
		t.Fatalf("development loopback URL was rejected: %v", err)
	}
}

func TestProductionSigningKeysRequirePersistentStore(t *testing.T) {
	if err := validateProductionKeyStorage(&Config{Environment: "production"}, true); err == nil {
		t.Fatal("production key set without persistent storage must fail closed")
	}
	if err := validateProductionKeyStorage(&Config{
		Environment:  "production",
		KeyStorePath: "/data/keys",
	}, true); err != nil {
		t.Fatalf("persistent production key store rejected: %v", err)
	}
	if err := validateProductionKeyStorage(&Config{Environment: "development"}, true); err != nil {
		t.Fatalf("ephemeral development key set rejected: %v", err)
	}
}
