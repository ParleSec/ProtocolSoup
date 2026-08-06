package plugin

import (
	"context"
	"fmt"
	"sync"
)

// State represents the lifecycle state of a plugin
type State int

const (
	StateUninitialized State = iota
	StateInitializing
	StateReady
	StateShuttingDown
	StateStopped
	StateError
)

func (s State) String() string {
	switch s {
	case StateUninitialized:
		return "uninitialized"
	case StateInitializing:
		return "initializing"
	case StateReady:
		return "ready"
	case StateShuttingDown:
		return "shutting_down"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// LifecycleManager tracks plugin states and handles lifecycle transitions
type LifecycleManager struct {
	states map[string]State
	errors map[string]error
	mu     sync.RWMutex
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager() *LifecycleManager {
	return &LifecycleManager{
		states: make(map[string]State),
		errors: make(map[string]error),
	}
}

// SetState sets the state for a plugin
func (lm *LifecycleManager) SetState(pluginID string, state State) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.states[pluginID] = state
	if state != StateError {
		delete(lm.errors, pluginID)
	}
}

// SetError sets an error state for a plugin
func (lm *LifecycleManager) SetError(pluginID string, err error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.states[pluginID] = StateError
	lm.errors[pluginID] = err
}

// Remove deletes lifecycle state for an unregistered plugin.
func (lm *LifecycleManager) Remove(pluginID string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.states, pluginID)
	delete(lm.errors, pluginID)
}

// GetState gets the state of a plugin
func (lm *LifecycleManager) GetState(pluginID string) State {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	if state, exists := lm.states[pluginID]; exists {
		return state
	}
	return StateUninitialized
}

// GetError gets any error for a plugin
func (lm *LifecycleManager) GetError(pluginID string) error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.errors[pluginID]
}

// IsReady checks if a plugin is ready
func (lm *LifecycleManager) IsReady(pluginID string) bool {
	return lm.GetState(pluginID) == StateReady
}

// AllReady checks if all plugins are ready
func (lm *LifecycleManager) AllReady() bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	for _, state := range lm.states {
		if state != StateReady {
			return false
		}
	}
	return true
}

// HealthCheck represents the health status of a plugin
type HealthCheck struct {
	PluginID string `json:"plugin_id"`
	State    string `json:"state"`
	Healthy  bool   `json:"healthy"`
	Error    string `json:"error,omitempty"`
}

// GetHealthChecks returns health status for all plugins
func (lm *LifecycleManager) GetHealthChecks() []HealthCheck {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	checks := make([]HealthCheck, 0, len(lm.states))
	for id, state := range lm.states {
		check := HealthCheck{
			PluginID: id,
			State:    state.String(),
			Healthy:  state == StateReady,
		}
		if err := lm.errors[id]; err != nil {
			check.Error = err.Error()
		}
		checks = append(checks, check)
	}
	return checks
}

// Hooks provides lifecycle hooks for plugins
type Hooks struct {
	OnInitialize func(ctx context.Context, pluginID string) error
	OnReady      func(pluginID string)
	OnShutdown   func(ctx context.Context, pluginID string) error
	OnError      func(pluginID string, err error)
}

// ManagedPlugin wraps a plugin with lifecycle management
type ManagedPlugin struct {
	plugin ProtocolPlugin
	lm     *LifecycleManager
	hooks  *Hooks
}

// NewManagedPlugin creates a managed plugin wrapper
func NewManagedPlugin(p ProtocolPlugin, lm *LifecycleManager, hooks *Hooks) *ManagedPlugin {
	return &ManagedPlugin{
		plugin: p,
		lm:     lm,
		hooks:  hooks,
	}
}

// Initialize initializes the managed plugin with lifecycle tracking
func (mp *ManagedPlugin) Initialize(ctx context.Context, config PluginConfig) error {
	id := mp.plugin.Info().ID

	mp.lm.SetState(id, StateInitializing)

	// Run pre-init hook
	if mp.hooks != nil && mp.hooks.OnInitialize != nil {
		if err := mp.hooks.OnInitialize(ctx, id); err != nil {
			mp.lm.SetError(id, err)
			return fmt.Errorf("pre-init hook failed: %w", err)
		}
	}

	// Initialize the plugin
	if err := mp.plugin.Initialize(ctx, config); err != nil {
		mp.lm.SetError(id, err)
		if mp.hooks != nil && mp.hooks.OnError != nil {
			mp.hooks.OnError(id, err)
		}
		return err
	}

	mp.lm.SetState(id, StateReady)

	// Run ready hook
	if mp.hooks != nil && mp.hooks.OnReady != nil {
		mp.hooks.OnReady(id)
	}

	return nil
}

// Shutdown shuts down the managed plugin with lifecycle tracking
func (mp *ManagedPlugin) Shutdown(ctx context.Context) error {
	id := mp.plugin.Info().ID

	mp.lm.SetState(id, StateShuttingDown)

	// Run shutdown hook
	if mp.hooks != nil && mp.hooks.OnShutdown != nil {
		if err := mp.hooks.OnShutdown(ctx, id); err != nil {
			mp.lm.SetError(id, err)
			return fmt.Errorf("shutdown hook failed: %w", err)
		}
	}

	// Shutdown the plugin
	if err := mp.plugin.Shutdown(ctx); err != nil {
		mp.lm.SetError(id, err)
		return err
	}

	mp.lm.SetState(id, StateStopped)
	return nil
}
