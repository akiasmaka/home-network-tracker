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

type UserSpaceMap struct {
	sync.Map
}

type ConnectionTracker struct {
	Data               UserSpaceMap
	expirationDuration time.Duration
	checkInterval      time.Duration
	kernelMap          *bpf.BPFMap
	l                  *zap.Logger
}

type ConnectionStats struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

type Connection struct {
	ConnectionStats
	Saddr string `json:"saddr"`
	Daddr string `json:"addr"`
	Type  int    `json:"type"`
}

type Entry struct {
	Connection  Connection `json:"connection"`
	LastUpdated int64      `json:"last_updated"`
}

type ConnectionKey = [64]byte

func (m *UserSpaceMap) ToSilce() []Connection {
	var conns []Connection
	m.Range(func(key, value any) bool {
		switch value.(type) {
		case Entry:
			conns = append(conns, value.(Entry).Connection)
		default:
			return false
		}
		return true
	})
	return conns
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
	m *bpf.BPFMap,
	l *zap.Logger) *ConnectionTracker {
	ct := &ConnectionTracker{
		Data:               UserSpaceMap{},
		expirationDuration: expirationDuration,
		checkInterval:      checkInterval,
		kernelMap:          m,
		l:                  l,
	}
	go ct.Monitor(ctx)
	return ct
}

func (m *ConnectionTracker) Store(k ConnectionKey, v Connection) {
	m.Data.Store(k, Entry{
		Connection:  v,
		LastUpdated: time.Now().UnixMilli(),
	})
}

func (m *ConnectionTracker) Load(key ConnectionKey) (Connection, bool) {
	if entry, exists := m.Data.Load(key); exists {
		return entry.(Entry).Connection, true
	}
	return Connection{}, false
}

func (m *ConnectionTracker) removeOldestEntry() {
	var oldestKey ConnectionKey
	var oldestTimestamp int64 = time.Now().UnixMilli()

	m.Data.Range(func(key, value any) bool {
		entry := value.(Entry)
		if entry.LastUpdated < oldestTimestamp {
			oldestTimestamp = entry.LastUpdated
			oldestKey = key.(ConnectionKey)
		}
		return true
	})

	m.Data.Delete(oldestKey)
	m.l.Sugar().Info("Removed oldest entry with timestamp: ", oldestTimestamp)
}

func (m *ConnectionTracker) Monitor(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixMilli()
			m.Data.Range(func(key, value any) bool {
				entry := value.(Entry)
				if now >= entry.LastUpdated+m.expirationDuration.Milliseconds() {
					m.OnExpire(key.(ConnectionKey))
					m.Data.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

func (m *ConnectionTracker) OnExpire(key ConnectionKey) {
	m.Data.Delete(key)
	if m.kernelMap != nil {
		k := key
		kPtr := unsafe.Pointer(&k[0])
		if err := m.kernelMap.DeleteKey(kPtr); err != nil {
			m.l.Sugar().Errorf("Failed to delete %v due to %v", key, err)
			panic("failed to delete")
		}
	} else {
		m.l.Sugar().Fatalf("Kernel map not set")
	}
}
