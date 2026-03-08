package output

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/history"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/network"
	ct "github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
	"github.com/andybalholm/brotli"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type Server struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Tracker *ct.ConnectionTracker
	History *history.HistoryStore
	WebDir  string
	Logger  *zap.Logger
}

func enableCors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func withCors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

type compressedResponseWriter struct {
	http.ResponseWriter
	writer io.Writer
}

func (w *compressedResponseWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

func selectEncoding(acceptEncoding string) string {
	acceptEncoding = strings.ToLower(acceptEncoding)
	if strings.Contains(acceptEncoding, "br") {
		return "br"
	}
	if strings.Contains(acceptEncoding, "gzip") {
		return "gzip"
	}
	return ""
}

func withCompression(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			next(w, r)
			return
		}

		encoding := selectEncoding(r.Header.Get("Accept-Encoding"))
		if encoding == "" {
			next(w, r)
			return
		}

		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Encoding", encoding)

		var writer io.WriteCloser
		switch encoding {
		case "br":
			writer = brotli.NewWriter(w)
		case "gzip":
			writer = gzip.NewWriter(w)
		default:
			next(w, r)
			return
		}
		defer func() {
			_ = writer.Close()
		}()

		next(&compressedResponseWriter{ResponseWriter: w, writer: writer}, r)
	}
}

type wsHub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

func newHub() *wsHub {
	return &wsHub{clients: make(map[*websocket.Conn]bool)}
}

func (h *wsHub) add(conn *websocket.Conn) {
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()
}

func (h *wsHub) remove(conn *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, conn)
	h.mu.Unlock()
	_ = conn.Close()
}

func (h *wsHub) broadcast(msg *websocket.PreparedMessage) {
	h.mu.Lock()
	for conn := range h.clients {
		if err := conn.WritePreparedMessage(msg); err != nil {
			delete(h.clients, conn)
			_ = conn.Close()
		}
	}
	h.mu.Unlock()
}

func (h *wsHub) broadcastLoop(ct *ct.ConnectionTracker) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if ct == nil {
			continue
		}
		payload, err := json.Marshal(history.SummarizeConnections(ct.Data.ToSlice()))
		if err != nil {
			continue
		}
		msg, err := websocket.NewPreparedMessage(websocket.TextMessage, payload)
		if err != nil {
			continue
		}
		h.broadcast(msg)
	}
}

func (s *Server) Serve() {
	mux := http.NewServeMux()

	hub := newHub()
	go hub.broadcastLoop(s.Tracker)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	mux.HandleFunc("/data", withCors(withCompression(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sortedConnections(s.Tracker))
	})))

	mux.HandleFunc("/api/connections", withCors(withCompression(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if s.Tracker == nil {
			_ = json.NewEncoder(w).Encode(connectionsResponse{Data: []ct.Connection{}, Total: 0})
			return
		}

		query := r.URL.Query()
		interfaceFilter := strings.TrimSpace(query.Get("interface"))
		directionFilter := strings.ToLower(strings.TrimSpace(query.Get("direction")))
		protoFilter := strings.ToLower(strings.TrimSpace(query.Get("proto")))
		containerFilter := strings.TrimSpace(query.Get("container"))
		search := strings.ToLower(strings.TrimSpace(query.Get("search")))
		sortField := strings.TrimSpace(query.Get("sort"))
		order := strings.ToLower(strings.TrimSpace(query.Get("order")))
		page := parseInt(query.Get("page"), 0)
		pageSize := parseInt(query.Get("pageSize"), 50)
		if page < 0 {
			page = 0
		}
		if pageSize <= 0 {
			pageSize = 50
		} else if pageSize > 200 {
			pageSize = 200
		}

		filtered := filterConnections(s.Tracker.Data.ToSlice(), connectionsQuery{
			Interface: interfaceFilter,
			Direction: directionFilter,
			Proto:     protoFilter,
			Container: containerFilter,
			Search:    search,
		})
		total := len(filtered)
		sortConnections(filtered, sortField, order)

		start := page * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		paged := filtered[start:end]

		_ = json.NewEncoder(w).Encode(connectionsResponse{Data: paged, Total: total})
	})))

	mux.HandleFunc("/ws", withCors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		hub.add(conn)
		go func() {
			defer hub.remove(conn)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))

	mux.HandleFunc("/api/history", withCors(withCompression(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if s.History == nil {
			_ = json.NewEncoder(w).Encode([]history.Snapshot{})
			return
		}

		rangeKey := r.URL.Query().Get("range")
		duration, ok := parseRange(rangeKey)
		if !ok && s.Logger != nil {
			s.Logger.Warn("Unknown history range; defaulting to 24h", zap.String("range", rangeKey))
		}
		since := time.Now().Add(-duration)
		queryStart := time.Now()
		snapshots, err := s.History.GetSnapshotsSince(since)
		elapsed := time.Since(queryStart)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Warn("History query failed", zap.String("range", rangeKey), zap.Duration("elapsed", elapsed), zap.Error(err))
			}
			http.Error(w, "History query failed", http.StatusInternalServerError)
			return
		}
		if s.Logger != nil && elapsed > 750*time.Millisecond {
			s.Logger.Warn("History query slow", zap.String("range", rangeKey), zap.Duration("elapsed", elapsed), zap.Int("count", len(snapshots)))
		}

		// ETag based on the last snapshot timestamp + count so unchanged
		// responses return 304 without re-serializing the full payload.
		etag := fmt.Sprintf(`"%s-%d"`, rangeKey, 0)
		if len(snapshots) > 0 {
			etag = fmt.Sprintf(`"%s-%d-%d"`, rangeKey, snapshots[len(snapshots)-1].Timestamp, len(snapshots))
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		if match := r.Header.Get("If-None-Match"); match == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		_ = json.NewEncoder(w).Encode(snapshots)
	})))

	webDir := s.WebDir
	if webDir == "" {
		webDir = "web/dist"
	}
	indexPath := filepath.Join(webDir, "index.html")

	mux.HandleFunc("/", withCors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		requestPath := filepath.Clean(r.URL.Path)
		if strings.Contains(requestPath, "..") {
			http.NotFound(w, r)
			return
		}

		ext := filepath.Ext(requestPath)
		filePath := filepath.Join(webDir, requestPath)
		if ext == "" {
			http.ServeFile(w, r, indexPath)
			return
		}

		if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
			http.ServeFile(w, r, filePath)
			return
		}
		http.NotFound(w, r)
	}))

	url := fmt.Sprintf("%s:%d", s.Addr, s.Port)
	fmt.Println("Server is running on ", url)
	if err := http.ListenAndServe(url, mux); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func parseRange(value string) (time.Duration, bool) {
	switch value {
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	default:
		return 24 * time.Hour, false
	}
}

type connectionsQuery struct {
	Interface string
	Direction string
	Proto     string
	Container string
	Search    string
}

type connectionsResponse struct {
	Data  []ct.Connection `json:"data"`
	Total int             `json:"total"`
}

func parseInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func filterConnections(conns []ct.Connection, query connectionsQuery) []ct.Connection {
	if len(conns) == 0 {
		return []ct.Connection{}
	}
	filtered := make([]ct.Connection, 0, len(conns))
	for _, conn := range conns {
		if query.Interface != "" && query.Interface != "all" {
			if interfaceName(conn) != query.Interface {
				continue
			}
		}
		if query.Direction != "" && query.Direction != "all" {
			switch query.Direction {
			case "ingress":
				if conn.Direction != network.DirectionIngress {
					continue
				}
			case "egress":
				if conn.Direction != network.DirectionEgress {
					continue
				}
			default:
				continue
			}
		}
		if query.Proto != "" && query.Proto != "all" {
			if protocolLabel(conn.Proto) != query.Proto {
				continue
			}
		}
		if query.Container != "" && query.Container != "all" {
			if strings.EqualFold(query.Container, "host") {
				if conn.Container != nil && conn.Container.ID != "" {
					continue
				}
			} else if conn.Container == nil || conn.Container.ID != query.Container {
				continue
			}
		}
		if query.Search != "" && !matchesSearch(conn, query.Search) {
			continue
		}
		filtered = append(filtered, conn)
	}
	return filtered
}

func matchesSearch(conn ct.Connection, query string) bool {
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(conn.Saddr), query) {
		return true
	}
	if strings.Contains(strings.ToLower(conn.Daddr), query) {
		return true
	}
	if strings.Contains(strings.ToLower(interfaceName(conn)), query) {
		return true
	}
	if strings.Contains(strings.ToLower(protocolLabel(conn.Proto)), query) {
		return true
	}
	if conn.Container != nil {
		if strings.Contains(strings.ToLower(conn.Container.ID), query) {
			return true
		}
		if strings.Contains(strings.ToLower(conn.Container.Name), query) {
			return true
		}
	}
	for _, name := range conn.SHost {
		if strings.Contains(strings.ToLower(name), query) {
			return true
		}
	}
	for _, name := range conn.DHost {
		if strings.Contains(strings.ToLower(name), query) {
			return true
		}
	}
	return false
}

func sortConnections(conns []ct.Connection, sortField, order string) {
	if len(conns) < 2 {
		return
	}
	field := strings.ToLower(strings.TrimSpace(sortField))
	if field == "" {
		field = "bytes"
	}
	if order != "asc" && order != "desc" {
		order = "desc"
	}
	useDesc := order == "desc"
	sort.Slice(conns, func(i, j int) bool {
		left := conns[i]
		right := conns[j]
		cmp := 0
		switch field {
		case "packets":
			cmp = compareUint64(left.Packets, right.Packets)
		case "saddr":
			cmp = compareString(left.Saddr, right.Saddr)
		case "addr", "daddr":
			cmp = compareString(left.Daddr, right.Daddr)
		case "ifname", "interface":
			cmp = compareString(interfaceName(left), interfaceName(right))
		case "direction":
			cmp = compareUint8(left.Direction, right.Direction)
		case "proto":
			cmp = compareString(protocolLabel(left.Proto), protocolLabel(right.Proto))
		case "container":
			cmp = compareString(containerName(left), containerName(right))
		default:
			cmp = compareUint64(left.Bytes, right.Bytes)
		}
		if useDesc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func interfaceName(conn ct.Connection) string {
	if conn.IfName != "" {
		return conn.IfName
	}
	return fmt.Sprintf("ifindex-%d", conn.IfIndex)
}

func containerName(conn ct.Connection) string {
	if conn.Container == nil {
		return "Host"
	}
	if conn.Container.Name != "" {
		return conn.Container.Name
	}
	if conn.Container.ID != "" {
		return conn.Container.ID
	}
	return "Host"
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

func compareString(left, right string) int {
	if left == right {
		return 0
	}
	if left < right {
		return -1
	}
	return 1
}

func compareUint64(left, right uint64) int {
	if left == right {
		return 0
	}
	if left < right {
		return -1
	}
	return 1
}

func compareUint8(left, right uint8) int {
	if left == right {
		return 0
	}
	if left < right {
		return -1
	}
	return 1
}

func sortedConnections(tracker *ct.ConnectionTracker) []ct.Connection {
	if tracker == nil {
		return []ct.Connection{}
	}
	data := tracker.Data.ToSlice()
	sort.Slice(data, func(i, j int) bool {
		if data[i].IfIndex == data[j].IfIndex {
			if data[i].CgroupID == data[j].CgroupID {
				if data[i].Direction == data[j].Direction {
					if data[i].Saddr == data[j].Saddr {
						return data[i].Daddr < data[j].Daddr
					}
					return data[i].Saddr < data[j].Saddr
				}
				return data[i].Direction < data[j].Direction
			}
			return data[i].CgroupID < data[j].CgroupID
		}
		return data[i].IfIndex < data[j].IfIndex
	})
	return data
}
