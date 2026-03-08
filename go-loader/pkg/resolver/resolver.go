package resolver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	cacheTTL = 1 * time.Hour
)

type cacheEntry struct {
	hostnames []string
	timestamp time.Time
}

// Resolver provides reverse DNS lookups using multiple sources
type Resolver struct {
	cache      sync.Map
	hosts      map[string][]string // /etc/hosts entries
	hostsMu    sync.RWMutex
	logger     *zap.Logger
	sniffers   map[string]*DNSSniffer
	sniffersMu sync.RWMutex
}

// NewResolver creates a new Resolver instance
func NewResolver(logger *zap.Logger) *Resolver {
	r := &Resolver{
		hosts:    make(map[string][]string),
		logger:   logger,
		sniffers: make(map[string]*DNSSniffer),
	}
	r.loadHostsFile()
	return r
}

// StartDNSSniffer starts the DNS sniffer BPF program on the given interfaces
func (r *Resolver) StartDNSSniffer(ctx context.Context, ifaces []string, bpfPath string) error {
	started := 0
	var lastErr error

	for _, iface := range ifaces {
		sniffer := NewDNSSniffer(r, iface, r.logger)
		if err := sniffer.Start(ctx, bpfPath); err != nil {
			lastErr = err
			r.logger.Warn("Failed to start DNS sniffer", zap.String("interface", iface), zap.Error(err))
			continue
		}
		r.sniffersMu.Lock()
		r.sniffers[iface] = sniffer
		r.sniffersMu.Unlock()
		started++
	}

	if started == 0 {
		return lastErr
	}
	return nil
}

// StopDNSSniffer stops the DNS sniffer
func (r *Resolver) StopDNSSniffer() {
	r.sniffersMu.Lock()
	defer r.sniffersMu.Unlock()
	for _, sniffer := range r.sniffers {
		sniffer.Stop()
	}
	r.sniffers = make(map[string]*DNSSniffer)
}

// loadHostsFile parses /etc/hosts and builds a reverse lookup map
func (r *Resolver) loadHostsFile() {
	file, err := os.Open("/etc/hosts")
	if err != nil {
		r.logger.Warn("Failed to open /etc/hosts", zap.Error(err))
		return
	}
	defer file.Close()

	r.hostsMu.Lock()
	defer r.hostsMu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		hostnames := fields[1:]

		// Validate IP
		if net.ParseIP(ip) == nil {
			continue
		}

		// Add or append hostnames for this IP
		if existing, ok := r.hosts[ip]; ok {
			r.hosts[ip] = append(existing, hostnames...)
		} else {
			r.hosts[ip] = hostnames
		}
	}

	r.logger.Info("Loaded /etc/hosts", zap.Int("entries", len(r.hosts)))
}

// lookupHosts checks /etc/hosts for the IP
func (r *Resolver) lookupHosts(ip string) []string {
	r.hostsMu.RLock()
	defer r.hostsMu.RUnlock()

	if hostnames, ok := r.hosts[ip]; ok {
		return hostnames
	}
	return nil
}

// LookupAddr performs a reverse DNS lookup for the given IP address
// It tries multiple sources in order:
// 1. /etc/hosts
// 2. Go's net.LookupAddr (PTR record lookup)
// 3. BPF DNS cache (from captured DNS responses)
// 4. Local Go cache
func (r *Resolver) LookupAddr(ip string) ([]string, error) {
	// Try /etc/hosts
	if hosts := r.lookupHosts(ip); len(hosts) > 0 {
		r.logger.Debug("Found in /etc/hosts", zap.String("ip", ip), zap.Strings("hosts", hosts))
		r.cacheResult(ip, hosts)
		return hosts, nil
	}

	// Fallback to Go's net.LookupAddr (PTR record lookup)
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		r.logger.Debug("net.LookupAddr resolved", zap.String("ip", ip), zap.Strings("hostnames", names))
		r.cacheResult(ip, names)
		return names, nil
	}

	if err != nil {
		r.logger.Debug("net.LookupAddr failed", zap.String("ip", ip), zap.Error(err))
	}

	// Try BPF DNS sniffer cache after PTR/hosts fail
	r.sniffersMu.RLock()
	for _, sniffer := range r.sniffers {
		if hostname, ok := sniffer.Lookup(ip); ok {
			r.sniffersMu.RUnlock()
			return []string{hostname}, nil
		}
	}
	r.sniffersMu.RUnlock()

	// Check local Go cache last
	if cached, ok := r.cache.Load(ip); ok {
		entry := cached.(cacheEntry)
		if time.Since(entry.timestamp) < cacheTTL {
			return entry.hostnames, nil
		}
		// Cache expired, remove it
		r.cache.Delete(ip)
	}

	return []string{""}, fmt.Errorf("no reverse DNS found for %s", ip)
}

// cacheResult stores a lookup result in the cache
func (r *Resolver) cacheResult(ip string, hostnames []string) {
	r.cache.Store(ip, cacheEntry{
		hostnames: hostnames,
		timestamp: time.Now(),
	})
}

// ClearCache clears the resolver cache
func (r *Resolver) ClearCache() {
	r.cache = sync.Map{}
}

// ReloadHosts reloads the /etc/hosts file
func (r *Resolver) ReloadHosts() {
	r.hostsMu.Lock()
	r.hosts = make(map[string][]string)
	r.hostsMu.Unlock()
	r.loadHostsFile()
}
