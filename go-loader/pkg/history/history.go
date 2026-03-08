package history

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/network"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
	"go.uber.org/zap"
)

type Snapshot struct {
	Timestamp int64   `json:"timestamp"`
	Summary   Summary `json:"summary"`
}

type Summary struct {
	TotalConnections int                         `json:"totalConnections"`
	BytesIn          uint64                      `json:"bytesIn"`
	BytesOut         uint64                      `json:"bytesOut"`
	PacketsIn        uint64                      `json:"packetsIn"`
	PacketsOut       uint64                      `json:"packetsOut"`
	UniqueSrcIPs     int                         `json:"uniqueSrcIps"`
	UniqueDstIPs     int                         `json:"uniqueDstIps"`
	PerInterface     map[string]InterfaceSummary `json:"perInterface"`
	PerProtocol      map[string]uint64           `json:"perProtocol"`
	PerContainer     map[string]ContainerSummary `json:"perContainer"`
	TopTalkers       []Talker                    `json:"topTalkers"`
}

type InterfaceSummary struct {
	Connections int    `json:"connections"`
	BytesIn     uint64 `json:"bytesIn"`
	BytesOut    uint64 `json:"bytesOut"`
	PacketsIn   uint64 `json:"packetsIn"`
	PacketsOut  uint64 `json:"packetsOut"`
}

type Talker struct {
	Addr  string `json:"addr"`
	Bytes uint64 `json:"bytes"`
}

type ContainerSummary struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Image           string   `json:"image"`
	Pid             int      `json:"pid"`
	Connections     int      `json:"connections"`
	BytesIn         uint64   `json:"bytesIn"`
	BytesOut        uint64   `json:"bytesOut"`
	PacketsIn       uint64   `json:"packetsIn"`
	PacketsOut      uint64   `json:"packetsOut"`
	TopDestinations []Talker `json:"topDestinations"`
}

// HistoryStore manages time-series snapshots and connection persistence using SQLite.
type HistoryStore struct {
	db      *DB
	tracker *tracker.ConnectionTracker
	l       *zap.Logger

	retention time.Duration
	interval  time.Duration

	// connSaveInterval controls how often connections are persisted (default 30s).
	connSaveInterval time.Duration
	lastConnSave     time.Time

	// maintenanceInterval controls how often downsampling + pruning runs.
	maintenanceInterval time.Duration
	lastMaintenance     time.Time
}

// NewHistoryStore creates a new SQLite-backed history store.
// dbPath is the path to the SQLite database file (e.g. /history/history.db).
func NewHistoryStore(dbPath string, retention, interval time.Duration, l *zap.Logger) (*HistoryStore, error) {
	db, err := OpenDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open history db: %w", err)
	}
	return &HistoryStore{
		db:                  db,
		retention:           retention,
		interval:            interval,
		l:                   l,
		connSaveInterval:    30 * time.Second,
		maintenanceInterval: 60 * time.Second,
	}, nil
}

// Close flushes pending connection state and closes the database.
func (h *HistoryStore) Close() error {
	if h.tracker != nil {
		if err := h.saveConnections(); err != nil {
			h.l.Warn("Failed to save connections on close", zap.Error(err))
		}
	}
	return h.db.Close()
}

// LoadConnections reads persisted connections from the database for tracker seeding.
func (h *HistoryStore) LoadConnections() ([]tracker.Entry, []tracker.ConnectionKey, error) {
	return h.db.LoadConnections()
}

// TakeSnapshot computes a summary from the current tracker state and inserts it.
func (h *HistoryStore) TakeSnapshot(ct *tracker.ConnectionTracker) error {
	if ct == nil {
		return fmt.Errorf("tracker is nil")
	}
	now := time.Now().UnixMilli()
	connections := ct.Data.ToSlice()
	summary := SummarizeConnections(connections)
	snapshot := Snapshot{
		Timestamp: now,
		Summary:   summary,
	}

	if err := h.db.InsertSnapshot(snapshot); err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}

	// Periodically save connections to disk.
	if time.Since(h.lastConnSave) >= h.connSaveInterval {
		if err := h.saveConnections(); err != nil {
			h.l.Warn("Failed to save connections", zap.Error(err))
		}
		h.lastConnSave = time.Now()
	}

	// Periodically downsample + prune.
	if time.Since(h.lastMaintenance) >= h.maintenanceInterval {
		if err := h.db.Downsample(now); err != nil {
			h.l.Warn("Downsample failed", zap.Error(err))
		}
		if err := h.db.Prune(now, h.retention.Milliseconds()); err != nil {
			h.l.Warn("Prune failed", zap.Error(err))
		}
		h.lastMaintenance = time.Now()
	}

	return nil
}

// StartSnapshotTicker starts a goroutine that takes snapshots at the configured interval.
func (h *HistoryStore) StartSnapshotTicker(ctx context.Context, ct *tracker.ConnectionTracker) {
	h.tracker = ct
	ticker := time.NewTicker(h.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := h.TakeSnapshot(ct); err != nil {
					h.l.Warn("Snapshot failed", zap.Error(err))
				}
			case <-ctx.Done():
				// Final save before shutdown.
				if err := h.saveConnections(); err != nil {
					h.l.Warn("Failed to save connections on shutdown", zap.Error(err))
				}
				return
			}
		}
	}()
}

// GetSnapshotsSince returns snapshots from the appropriate tier for the given time range.
func (h *HistoryStore) GetSnapshotsSince(since time.Time) ([]Snapshot, error) {
	sinceMs := since.UnixMilli()
	nowMs := time.Now().UnixMilli()
	snapshots, err := h.db.QuerySnapshots(sinceMs, nowMs)
	if err != nil {
		return nil, err
	}
	return snapshots, nil
}

// saveConnections persists the current tracker state to the database.
func (h *HistoryStore) saveConnections() error {
	if h.tracker == nil {
		return nil
	}
	entries, keys := h.tracker.Data.ToEntries()
	return h.db.SaveConnections(entries, keys)
}

// --- Summary computation (unchanged logic) ---

func SummarizeConnections(conns []tracker.Connection) Summary {
	perInterface := make(map[string]InterfaceSummary)
	perProtocol := make(map[string]uint64)
	perContainer := make(map[string]ContainerSummary)
	containerDestinations := make(map[string]map[string]uint64)
	srcIPs := make(map[string]struct{})
	dstIPs := make(map[string]struct{})
	talkerBytes := make(map[string]uint64)

	summary := Summary{
		TotalConnections: len(conns),
		PerInterface:     perInterface,
		PerProtocol:      perProtocol,
		PerContainer:     perContainer,
	}

	for _, conn := range conns {
		if conn.Saddr != "" {
			srcIPs[conn.Saddr] = struct{}{}
		}
		if conn.Daddr != "" {
			dstIPs[conn.Daddr] = struct{}{}
		}

		containerKey := "host"
		containerName := "Host"
		containerImage := ""
		containerPid := 0
		if conn.Container != nil {
			if conn.Container.ID != "" {
				containerKey = conn.Container.ID
			}
			if conn.Container.Name != "" {
				containerName = conn.Container.Name
			} else if conn.Container.ID != "" {
				containerName = conn.Container.ID
			}
			if conn.Container.Image != "" {
				containerImage = conn.Container.Image
			}
			if conn.Container.Pid != 0 {
				containerPid = conn.Container.Pid
			}
		}
		container := perContainer[containerKey]
		if container.ID == "" {
			container.ID = containerKey
		}
		if container.Name == "" {
			container.Name = containerName
		}
		if container.Image == "" && containerImage != "" {
			container.Image = containerImage
		}
		if container.Pid == 0 && containerPid != 0 {
			container.Pid = containerPid
		}
		container.Connections++

		if conn.Daddr != "" {
			talkerBytes[conn.Daddr] += conn.Bytes
			bucket := containerDestinations[containerKey]
			if bucket == nil {
				bucket = make(map[string]uint64)
				containerDestinations[containerKey] = bucket
			}
			bucket[conn.Daddr] += conn.Bytes
		}

		protoLabel := protocolLabel(conn.Proto)
		perProtocol[protoLabel]++

		ifName := conn.IfName
		if ifName == "" {
			ifName = fmt.Sprintf("ifindex-%d", conn.IfIndex)
		}
		iface := perInterface[ifName]
		iface.Connections++

		switch conn.Direction {
		case network.DirectionIngress:
			summary.BytesIn += conn.Bytes
			summary.PacketsIn += conn.Packets
			iface.BytesIn += conn.Bytes
			iface.PacketsIn += conn.Packets
			container.BytesIn += conn.Bytes
			container.PacketsIn += conn.Packets
		case network.DirectionEgress:
			summary.BytesOut += conn.Bytes
			summary.PacketsOut += conn.Packets
			iface.BytesOut += conn.Bytes
			iface.PacketsOut += conn.Packets
			container.BytesOut += conn.Bytes
			container.PacketsOut += conn.Packets
		default:
		}

		perInterface[ifName] = iface
		perContainer[containerKey] = container
	}

	for key, container := range perContainer {
		if destinations, ok := containerDestinations[key]; ok {
			container.TopDestinations = topTalkers(destinations, 3)
		} else {
			container.TopDestinations = []Talker{}
		}
		perContainer[key] = container
	}

	summary.UniqueSrcIPs = len(srcIPs)
	summary.UniqueDstIPs = len(dstIPs)
	summary.TopTalkers = topTalkers(talkerBytes, 10)

	return summary
}

func protocolLabel(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "other"
	}
}

func topTalkers(bytesByAddr map[string]uint64, limit int) []Talker {
	if limit <= 0 || len(bytesByAddr) == 0 {
		return []Talker{}
	}

	talkers := make([]Talker, 0, len(bytesByAddr))
	for addr, bytes := range bytesByAddr {
		talkers = append(talkers, Talker{Addr: addr, Bytes: bytes})
	}

	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Bytes > talkers[j].Bytes
	})

	if len(talkers) > limit {
		return talkers[:limit]
	}
	return talkers
}
