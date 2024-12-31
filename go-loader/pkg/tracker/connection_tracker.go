package tracker

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"go.uber.org/zap"
)

type ConnectionTracker struct {
	data               sync.Map
	expirationDuration time.Duration
	checkInterval      time.Duration
	maxSize            int
	kernelMap          *bpf.BPFMap
	l                  *zap.Logger
}

type ConnectionKey struct {
	Key       any
	KernelKey [64]byte // make it an array so that i can be hashable. TODO: picked 64 for now but that might not be right?
}

type ConnectionStats struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Entry struct {
	data        ConnectionStats
	lastUpdated int64
}

func ParseConnectionStats(stats []byte) (ConnectionStats, error) {
	var d ConnectionStats
	r := bytes.NewReader(stats)
	err := binary.Read(r, binary.NativeEndian, &d)
	return d, err
}

func NewConnectionTracker(ctx context.Context,
	expirationDuration,
	checkInterval time.Duration,
	maxSize int,
	m *bpf.BPFMap,
	l *zap.Logger) *ConnectionTracker {
	ct := &ConnectionTracker{
		data:               sync.Map{},
		expirationDuration: expirationDuration,
		checkInterval:      checkInterval,
		maxSize:            maxSize,
		kernelMap:          m,
		l:                  l,
	}
	go ct.Monitor(ctx)
	return ct
}

func (m *ConnectionTracker) Store(key ConnectionKey, value ConnectionStats) {
	m.data.Store(key, Entry{
		data:        value,
		lastUpdated: time.Now().UnixMilli(),
	})
}

func (m *ConnectionTracker) Load(key ConnectionKey) (ConnectionStats, bool) {
	if entry, exists := m.data.Load(key); exists {
		return entry.(Entry).data, true // would be "defensive" to type assert here and in other places but w/e
	}
	return ConnectionStats{}, false
}

func (m *ConnectionTracker) Monitor(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.data.Range(func(key, value any) bool {
				entry := value.(Entry)
				m.l.Sugar().Infof("Checking key %v at time %v with lastUpdated %v", key, time.Now().UnixMilli(), entry.lastUpdated)
				if time.Now().UnixMilli() >= entry.lastUpdated+m.expirationDuration.Milliseconds() {
					m.OnExpire(key.(ConnectionKey))
					m.data.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

func (m *ConnectionTracker) OnExpire(key ConnectionKey) {
	m.data.Delete(key)
	if m.kernelMap != nil {
		k := key.KernelKey
		kPtr := unsafe.Pointer(&k[0])
		if err := m.kernelMap.DeleteKey(kPtr); err != nil {
			m.l.Sugar().Errorf("Failed to delete %v due to %v", key, err)
			panic("failed to delete")
		} else {
			m.l.Sugar().Infof("Deleted ", key.Key)
		}
	} else {
		m.l.Sugar().Fatalf("Kernel map not set")
	}
}
