package listeners

import (
	"fmt"
	"sync"

	"github.com/shehzade/contraband/pkg/common"
)

// ListenerRegistry coordinates dedicated L7 listeners and claims dedicated ports.
type ListenerRegistry struct {
	mu        sync.RWMutex
	listeners map[string]ProtocolListener
	portClaim map[int]string // port -> listener name
	logger    common.Logger
}

// NewListenerRegistry constructs a clean registry instance.
func NewListenerRegistry(logger common.Logger) *ListenerRegistry {
	return &ListenerRegistry{
		listeners: make(map[string]ProtocolListener),
		portClaim: make(map[int]string),
		logger:    logger,
	}
}

// Register adds a ProtocolListener and records its claimed ports.
func (r *ListenerRegistry) Register(listener ProtocolListener) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := listener.Name()
	if _, exists := r.listeners[name]; exists {
		return fmt.Errorf("listener %q already registered", name)
	}

	for _, port := range listener.Ports() {
		if claimedBy, exists := r.portClaim[port]; exists {
			return fmt.Errorf("port %d already claimed by %q", port, claimedBy)
		}
	}

	for _, port := range listener.Ports() {
		r.portClaim[port] = name
	}
	r.listeners[name] = listener
	return nil
}

// IsPortClaimed returns true if a dedicated protocol listener owns the port.
func (r *ListenerRegistry) IsPortClaimed(port int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, claimed := r.portClaim[port]
	return claimed
}

// FilterMultiplexPorts removes dedicated listener ports from the sweep multiplexer list.
func (r *ListenerRegistry) FilterMultiplexPorts(ports []int) []int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, claimed := r.portClaim[port]; !claimed {
			filtered = append(filtered, port)
		}
	}
	return filtered
}

// GetListener returns a registered listener by name.
func (r *ListenerRegistry) GetListener(name string) (ProtocolListener, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.listeners[name]
	return l, ok
}

// GetAllListeners returns all registered protocol listeners.
func (r *ListenerRegistry) GetAllListeners() []ProtocolListener {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]ProtocolListener, 0, len(r.listeners))
	for _, l := range r.listeners {
		res = append(res, l)
	}
	return res
}
