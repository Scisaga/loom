package dnsprovider

import (
	"context"
	"sync"
	"time"
)

// Memory 是测试/开发 adapter；它与真实 provider 一样做 write 后 readback，
// 但不把本地 map 当成 certified authority。
type Memory struct {
	mu      sync.Mutex
	records map[[3]string]RRSet
	now     func() time.Time
}

func NewMemory() *Memory {
	return &Memory{records: make(map[[3]string]RRSet), now: time.Now}
}

func (m *Memory) Read(_ context.Context, zone, name, rrType string) (Readback, error) {
	probe, err := Normalize(RRSet{Zone: zone, Name: name, Type: rrType, TTL: 60, Values: []string{lookupPlaceholder(rrType)}})
	if err != nil {
		return Readback{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.records[[3]string{probe.Zone, probe.Name, probe.Type}]
	if !ok {
		return Readback{}, ErrNotFound
	}
	return Readback{RRSet: set, ObservedAt: m.now().UTC()}, nil
}

func (m *Memory) Replace(_ context.Context, desired RRSet) (Readback, error) {
	desired, err := Normalize(desired)
	if err != nil {
		return Readback{}, err
	}
	m.mu.Lock()
	m.records[[3]string{desired.Zone, desired.Name, desired.Type}] = desired
	m.mu.Unlock()
	return m.Read(context.Background(), desired.Zone, desired.Name, desired.Type)
}

func (m *Memory) Delete(_ context.Context, zone, name, rrType string) error {
	probe, err := Normalize(RRSet{Zone: zone, Name: name, Type: rrType, TTL: 60, Values: []string{lookupPlaceholder(rrType)}})
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.records, [3]string{probe.Zone, probe.Name, probe.Type})
	m.mu.Unlock()
	return nil
}
