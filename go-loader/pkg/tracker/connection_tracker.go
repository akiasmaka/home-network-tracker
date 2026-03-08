package tracker

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/containermeta"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/network"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/resolver"
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
	kernelMapV4        *bpf.BPFMap
	kernelMapV6        *bpf.BPFMap
	l                  *zap.Logger
	resolver           *resolver.Resolver
	containerResolver  *containermeta.Resolver
	ctx                context.Context
}

type ConnectionStats struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Connection struct {
	ConnectionStats
	Saddr     string                       `json:"saddr"`
	Daddr     string                       `json:"addr"`
	IfIndex   uint32                       `json:"ifindex"`
	IfName    string                       `json:"ifname"`
	CgroupID  uint64                       `json:"cgroupId"`
	Direction uint8                        `json:"direction"`
	Proto     uint8                        `json:"proto"`
	SHost     []string                     `json:"sHost"`
	DHost     []string                     `json:"dHost"`
	Container *containermeta.ContainerInfo `json:"container,omitempty"`
	Type      int                          `json:"type"`
}

type Entry struct {
	Connection  Connection `json:"connection"`
	LastUpdated int64      `json:"last_updated"`
}

type ConnectionKey = [64]byte

// ToSlice returns all tracked connections as a slice.
func (m *UserSpaceMap) ToSlice() []Connection {
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

// Deprecated: Use ToSlice instead.
func (m *UserSpaceMap) ToSilce() []Connection {
	return m.ToSlice()
}

// ToEntries returns all tracked entries with their keys, preserving LastUpdated timestamps.
func (m *UserSpaceMap) ToEntries() ([]Entry, []ConnectionKey) {
	var entries []Entry
	var keys []ConnectionKey
	m.Range(func(key, value any) bool {
		switch v := value.(type) {
		case Entry:
			entries = append(entries, v)
			keys = append(keys, key.(ConnectionKey))
		default:
			return false
		}
		return true
	})
	return entries, keys
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
	mapV4 *bpf.BPFMap,
	mapV6 *bpf.BPFMap,
	ifaces []string,
	dnsBpfPath string,
	l *zap.Logger) *ConnectionTracker {
	r := resolver.NewResolver(l)

	// Start DNS sniffer BPF program to capture hostnames from DNS responses
	if err := r.StartDNSSniffer(ctx, ifaces, dnsBpfPath); err != nil {
		l.Warn("Failed to start DNS sniffer", zap.Error(err))
	}

	containerResolver, err := containermeta.NewResolver(ctx, l, 2*time.Minute)
	if err != nil {
		l.Warn("Failed to initialize Docker metadata resolver", zap.Error(err))
	}

	ct := &ConnectionTracker{
		Data:               UserSpaceMap{},
		expirationDuration: expirationDuration,
		checkInterval:      checkInterval,
		kernelMapV4:        mapV4,
		kernelMapV6:        mapV6,
		l:                  l,
		resolver:           r,
		containerResolver:  containerResolver,
		ctx:                ctx,
	}
	go ct.Monitor(ctx)
	return ct
}

func (m *ConnectionTracker) Store(k ConnectionKey, v Connection) {
	if entry, ok := m.Data.Load(k); ok {
		existing := entry.(Entry).Connection
		// Accumulate stats from the kernel delta into the running total.
		v.Packets += existing.Packets
		v.Bytes += existing.Bytes
		v.SHost = existing.SHost
		// can happen if the saved data has no SHost/DHost entry
		if v.SHost == nil {
			v.SHost = []string{""}
		}
		v.DHost = existing.DHost
		if v.DHost == nil {
			v.DHost = []string{""}
		}
		if v.Container == nil {
			v.Container = existing.Container
		}
		m.enrichContainer(&v)
		v.CgroupID = 0

		m.Data.Store(k, Entry{
			Connection:  v,
			LastUpdated: time.Now().UnixMilli(),
		})
	} else {
		var err error
		v.SHost, err = m.resolver.LookupAddr(v.Saddr)
		if err != nil {
			m.l.Sugar().Warnf("lookup for saddr %s failed with: %s", v.Saddr, err)
			v.SHost = []string{""}
		}
		v.DHost, err = m.resolver.LookupAddr(v.Daddr)
		if err != nil {
			m.l.Sugar().Warnf("lookup for daddr %s failed with: %s", v.Daddr, err)
			v.DHost = []string{""}
		}
		m.enrichContainer(&v)
		v.CgroupID = 0

		m.Data.Store(k, Entry{
			Connection:  v,
			LastUpdated: time.Now().UnixMilli(),
		})
	}
}

func (m *ConnectionTracker) enrichContainer(conn *Connection) {
	if conn == nil || conn.Container != nil {
		return
	}
	if m.containerResolver == nil || conn.CgroupID == 0 {
		return
	}
	if info := m.containerResolver.LookupCgroupID(conn.CgroupID); info != nil {
		conn.Container = info
		return
	}
	if m.containerResolver.RefreshIfStale(m.ctx, 15*time.Second) {
		if info := m.containerResolver.LookupCgroupID(conn.CgroupID); info != nil {
			conn.Container = info
		}
	}
}

func (m *ConnectionTracker) Load(key ConnectionKey) (Connection, bool) {
	if entry, exists := m.Data.Load(key); exists {
		return entry.(Entry).Connection, true
	}
	return Connection{}, false
}

func (m *ConnectionTracker) ContainerResolver() *containermeta.Resolver {
	return m.containerResolver
}

func (m *ConnectionTracker) ResolveContainer(cgroupID uint64) *containermeta.ContainerInfo {
	if m == nil || m.containerResolver == nil || cgroupID == 0 {
		return nil
	}
	if info := m.containerResolver.LookupCgroupID(cgroupID); info != nil {
		return info
	}
	if m.containerResolver.RefreshIfStale(m.ctx, 15*time.Second) {
		if info := m.containerResolver.LookupCgroupID(cgroupID); info != nil {
			return info
		}
	}
	return nil
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
					m.OnExpire(key.(ConnectionKey), entry.Connection.Type)
					m.Data.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

func (m *ConnectionTracker) OnExpire(key ConnectionKey, connType int) {
	// Kernel map entries are deleted after read. Nothing to do here.
	return
}

// SeedEntries loads pre-parsed entries (with preserved LastUpdated timestamps) into
// the tracker's in-memory map. This avoids resetting TTL on restart.
func (m *ConnectionTracker) SeedEntries(entries []Entry, keys []ConnectionKey) {
	for i, entry := range entries {
		conn := entry.Connection
		if conn.Direction == network.DirectionUnknown {
			conn.Direction = network.DirectionIngress
		}
		m.Data.Store(keys[i], Entry{
			Connection:  conn,
			LastUpdated: entry.LastUpdated,
		})
	}
}

// SeedConnections loads pre-parsed connections into the tracker's in-memory map.
// Note: LastUpdated is set to time.Now() — use SeedEntries to preserve timestamps.
func (m *ConnectionTracker) SeedConnections(conns []Connection) {
	for _, conn := range conns {
		if conn.Direction == network.DirectionUnknown {
			conn.Direction = network.DirectionIngress
		}
		ipKey := network.IPKey{
			Saddr:     conn.Saddr,
			Daddr:     conn.Daddr,
			IfIndex:   conn.IfIndex,
			CgroupID:  0,
			Direction: conn.Direction,
			Proto:     conn.Proto,
			Type:      conn.Type,
		}
		x := network.GenericToIp(ipKey)
		key := network.IpToKernelKey(x)
		m.Store(key, conn)
	}
}

func (m *ConnectionTracker) LogData() {
	m.Data.Range(func(key, value any) bool {
		entry := value.(Entry)
		m.l.Sugar().Infof("Key: %v, Value: %v", key, entry)
		return true
	})
}
