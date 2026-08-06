package plugin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/go-chi/chi/v5"
)

type registryTestPlugin struct {
	id            string
	initializeErr error
	shutdownOrder *[]string
}

func (p *registryTestPlugin) Info() PluginInfo { return PluginInfo{ID: p.id, Name: p.id} }
func (p *registryTestPlugin) Initialize(context.Context, PluginConfig) error {
	return p.initializeErr
}
func (p *registryTestPlugin) Shutdown(context.Context) error {
	if p.shutdownOrder != nil {
		*p.shutdownOrder = append(*p.shutdownOrder, p.id)
	}
	return nil
}
func (p *registryTestPlugin) RegisterRoutes(chi.Router)            {}
func (p *registryTestPlugin) GetInspectors() []Inspector           { return nil }
func (p *registryTestPlugin) GetFlowDefinitions() []FlowDefinition { return nil }
func (p *registryTestPlugin) GetDemoScenarios() []DemoScenario     { return nil }

func TestRegistryTracksLifecycleInRegistrationOrder(t *testing.T) {
	registry := NewRegistry()
	shutdownOrder := make([]string, 0, 2)
	for _, id := range []string{"first", "second"} {
		if err := registry.Register(&registryTestPlugin{id: id, shutdownOrder: &shutdownOrder}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}

	checks := registry.HealthChecks()
	if got := []string{checks[0].PluginID, checks[1].PluginID}; !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("health check order = %v", got)
	}
	for _, check := range checks {
		if check.State != StateUninitialized.String() || check.Healthy {
			t.Fatalf("initial check = %+v", check)
		}
	}

	if err := registry.InitializeAll(context.Background(), PluginConfig{}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if !registry.AllReady() {
		t.Fatal("registry should be ready after successful initialization")
	}
	for _, check := range registry.HealthChecks() {
		if check.State != StateReady.String() || !check.Healthy {
			t.Fatalf("ready check = %+v", check)
		}
	}

	if err := registry.ShutdownAll(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !reflect.DeepEqual(shutdownOrder, []string{"second", "first"}) {
		t.Fatalf("shutdown order = %v", shutdownOrder)
	}
	for _, check := range registry.HealthChecks() {
		if check.State != StateStopped.String() || check.Healthy {
			t.Fatalf("stopped check = %+v", check)
		}
	}
}

func TestRegistryRecordsInitializationFailure(t *testing.T) {
	registry := NewRegistry()
	wantErr := errors.New("initialization failed")
	if err := registry.Register(&registryTestPlugin{id: "broken", initializeErr: wantErr}); err != nil {
		t.Fatalf("register: %v", err)
	}

	err := registry.InitializeAll(context.Background(), PluginConfig{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("initialize error = %v, want %v", err, wantErr)
	}
	check := registry.HealthChecks()[0]
	if check.State != StateError.String() || check.Healthy || check.Error != wantErr.Error() {
		t.Fatalf("failure check = %+v", check)
	}
}
