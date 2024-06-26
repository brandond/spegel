package routing

import (
	"context"
	"net/netip"
	"sync"
)

type MemoryRouter struct {
	resolver map[string][]netip.AddrPort
	self     netip.AddrPort
	mx       sync.RWMutex
}

func NewMemoryRouter(resolver map[string][]netip.AddrPort, self netip.AddrPort) *MemoryRouter {
	return &MemoryRouter{
		resolver: resolver,
		self:     self,
	}
}

func (m *MemoryRouter) Ready(ctx context.Context) (bool, error) {
	m.mx.RLock()
	defer m.mx.RUnlock()
	return len(m.resolver) > 0, nil
}

func (m *MemoryRouter) Resolve(ctx context.Context, key string, allowSelf bool, count int) (<-chan netip.AddrPort, error) {
	peerCh := make(chan netip.AddrPort, count)
	m.mx.RLock()
	peers, ok := m.resolver[key]
	m.mx.RUnlock()
	// If not peers exist close the channel to stop any consumer.
	if !ok {
		close(peerCh)
		return peerCh, nil
	}
	go func() {
		for _, peer := range peers {
			peerCh <- peer
		}
		close(peerCh)
	}()
	return peerCh, nil
}

func (m *MemoryRouter) Advertise(ctx context.Context, keys []string) error {
	for _, key := range keys {
		m.Add(key, m.self)
	}
	return nil
}

func (m *MemoryRouter) Add(key string, ap netip.AddrPort) {
	m.mx.Lock()
	defer m.mx.Unlock()
	if v, ok := m.resolver[key]; ok {
		m.resolver[key] = append(v, ap)
		return
	}
	m.resolver[key] = []netip.AddrPort{ap}
}

func (m *MemoryRouter) Lookup(key string) ([]netip.AddrPort, bool) {
	m.mx.RLock()
	defer m.mx.RUnlock()
	v, ok := m.resolver[key]
	return v, ok
}
