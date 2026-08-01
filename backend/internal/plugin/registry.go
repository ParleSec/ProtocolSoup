package plugin

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Registry manages protocol plugins
type Registry struct {
	plugins map[string]ProtocolPlugin
	order   []string // Maintain registration order
	mu      sync.RWMutex
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]ProtocolPlugin),
		order:   make([]string, 0),
	}
}

// Register adds a plugin to the registry
func (r *Registry) Register(p ProtocolPlugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info := p.Info()
	if info.ID == "" {
		return fmt.Errorf("plugin ID cannot be empty")
	}

	if _, exists := r.plugins[info.ID]; exists {
		return fmt.Errorf("plugin %s already registered", info.ID)
	}

	r.plugins[info.ID] = p
	r.order = append(r.order, info.ID)

	log.Printf("Registered plugin: %s (%s)", info.Name, info.ID)
	return nil
}

// Unregister removes a plugin from the registry
func (r *Registry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[id]; !exists {
		return fmt.Errorf("plugin %s not found", id)
	}

	delete(r.plugins, id)

	// Remove from order slice
	for i, pid := range r.order {
		if pid == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}

	log.Printf("Unregistered plugin: %s", id)
	return nil
}

// Get retrieves a plugin by ID
func (r *Registry) Get(id string) (ProtocolPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.plugins[id]
	return p, exists
}

// List returns all registered plugins in registration order
func (r *Registry) List() []ProtocolPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]ProtocolPlugin, len(r.order))
	for i, id := range r.order {
		plugins[i] = r.plugins[id]
	}
	return plugins
}

// InitializeAll initializes all registered plugins
func (r *Registry) InitializeAll(ctx context.Context, config PluginConfig) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, id := range r.order {
		p := r.plugins[id]
		if err := p.Initialize(ctx, config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", id, err)
		}
		log.Printf("Initialized plugin: %s", id)
	}
	return nil
}

// ShutdownAll shuts down all registered plugins in reverse order
func (r *Registry) ShutdownAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lastErr error
	// Shutdown in reverse order
	for i := len(r.order) - 1; i >= 0; i-- {
		id := r.order[i]
		p := r.plugins[id]
		if err := p.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down plugin %s: %v", id, err)
			lastErr = err
		} else {
			log.Printf("Shut down plugin: %s", id)
		}
	}
	return lastErr
}

// Count returns the number of registered plugins
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}
