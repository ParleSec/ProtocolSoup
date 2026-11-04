package main

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func TestResolveOriginsOffersOnlyProductionOrLocalhost(t *testing.T) {
	production, err := resolveOrigins("production", false, 8080, 0, 0, false)
	if err != nil || production != capture.ProductionOrigins() {
		t.Fatalf("production = %+v, %v", production, err)
	}
	local, err := resolveOrigins("local", true, 8181, 8282, 8383, false)
	want := capture.Origins{Base: "http://localhost:8181", Wallet: "http://localhost:8282", Counterparty: "http://localhost:8383"}
	if err != nil || local != want {
		t.Fatalf("local = %+v, %v", local, err)
	}
	for name, call := range map[string]func() (capture.Origins, error){
		"missing target": func() (capture.Origins, error) { return resolveOrigins("", false, 8080, 0, 0, false) },
		"unknown target": func() (capture.Origins, error) {
			return resolveOrigins("https://example.com", false, 8080, 0, 0, false)
		},
		"ports with production":   func() (capture.Origins, error) { return resolveOrigins("production", true, 9000, 0, 0, false) },
		"out-of-range local port": func() (capture.Origins, error) { return resolveOrigins("local", true, 70000, 0, 0, false) },
		"two counterparties":      func() (capture.Origins, error) { return resolveOrigins("local", true, 8181, 0, 8383, true) },
	} {
		if origins, err := call(); err == nil {
			t.Fatalf("%s: got %+v; want an error", name, origins)
		}
	}
}
