package containermeta

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type ContainerInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Image      string `json:"image"`
	Pid        int    `json:"pid"`
	CgroupPath string `json:"cgroupPath"`
}

type Resolver struct {
	client          *http.Client
	logger          *zap.Logger
	refreshInterval time.Duration
	mu              sync.RWMutex
	byCgroupID      map[uint64]*ContainerInfo
	lastRefresh     time.Time
}

func NewResolver(ctx context.Context, logger *zap.Logger, refreshInterval time.Duration) (*Resolver, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	r := &Resolver{
		client:          client,
		logger:          logger,
		refreshInterval: refreshInterval,
		byCgroupID:      make(map[uint64]*ContainerInfo),
	}

	r.refresh(ctx)
	go r.run(ctx)
	return r, nil
}

func (r *Resolver) LookupCgroupID(cgroupID uint64) *ContainerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if info, ok := r.byCgroupID[cgroupID]; ok {
		return info
	}
	return nil
}

func (r *Resolver) Snapshot() []ContainerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]ContainerInfo, 0, len(r.byCgroupID))
	for _, info := range r.byCgroupID {
		if info == nil {
			continue
		}
		entries = append(entries, *info)
	}
	return entries
}

func (r *Resolver) RefreshIfStale(ctx context.Context, minInterval time.Duration) bool {
	r.mu.RLock()
	lastRefresh := r.lastRefresh
	r.mu.RUnlock()
	if time.Since(lastRefresh) < minInterval {
		return false
	}
	r.refresh(ctx)
	return true
}

func (r *Resolver) run(ctx context.Context) {
	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

func (r *Resolver) refresh(ctx context.Context) {
	refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(refreshCtx, http.MethodGet, "http://unix/containers/json?all=1", nil)
	if err != nil {
		r.logger.Warn("Failed to create Docker API request", zap.Error(err))
		return
	}

	response, err := r.client.Do(request)
	if err != nil {
		r.logger.Warn("Failed to query Docker API", zap.Error(err))
		return
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		r.logger.Warn("Docker API returned error", zap.Int("status", response.StatusCode))
		return
	}

	var containers []dockerContainer
	if err := json.NewDecoder(response.Body).Decode(&containers); err != nil {
		r.logger.Warn("Failed to decode Docker API response", zap.Error(err))
		return
	}

	// First pass: build info for all containers, track network_mode:container:* relationships.
	type containerEntry struct {
		info     *ContainerInfo
		cgroupID uint64
		// networkParentID is set when NetworkMode is "container:<id>".
		networkParentID string
	}
	entries := make([]containerEntry, 0, len(containers))
	containerIDToCgroupID := make(map[string]uint64)

	for _, container := range containers {
		name := container.ID
		if len(container.Names) > 0 {
			name = strings.TrimPrefix(container.Names[0], "/")
		}
		info := &ContainerInfo{ID: container.ID, Name: name, Image: container.Image}
		result, err := r.inspectContainer(refreshCtx, container.ID)
		if err != nil || result.Pid == 0 {
			r.logger.Warn("Failed to resolve container PID", zap.String("name", name), zap.String("id", container.ID), zap.Error(err))
			continue
		}
		info.Pid = result.Pid

		cgroupPath, err := readCgroupPath(result.Pid)
		if err != nil {
			r.logger.Warn("Failed to read cgroup path", zap.Int("pid", result.Pid), zap.Error(err))
			continue
		}
		fullPath := cgroupFullPath(cgroupPath)
		info.CgroupPath = fullPath
		cgroupID, err := cgroupIDFromFullPath(fullPath)
		if err != nil {
			r.logger.Debug("Failed to resolve cgroup ID", zap.String("name", name), zap.String("path", cgroupPath), zap.Error(err))
			continue
		}

		var networkParentID string
		if strings.HasPrefix(result.NetworkMode, "container:") {
			networkParentID = strings.TrimPrefix(result.NetworkMode, "container:")
			r.logger.Debug("Container shares network namespace",
				zap.String("name", name),
				zap.String("networkParent", networkParentID))
		}

		containerIDToCgroupID[container.ID] = cgroupID
		entries = append(entries, containerEntry{info: info, cgroupID: cgroupID, networkParentID: networkParentID})
	}

	// Second pass: for containers sharing a network namespace (network_mode: container:<id>),
	// also register them under the parent container's cgroup ID so that when the kernel reports
	// the parent's cgroup ID we can still look them up.
	updated := make(map[uint64]*ContainerInfo)
	for _, entry := range entries {
		updated[entry.cgroupID] = entry.info

		if entry.networkParentID != "" {
			if parentCgroupID, ok := containerIDToCgroupID[entry.networkParentID]; ok {
				// Ensure the parent's cgroup path is included so the eBPF program gets attached to it.
				if _, exists := updated[parentCgroupID]; !exists {
					// Find the parent entry and add it.
					for _, pe := range entries {
						if pe.cgroupID == parentCgroupID {
							updated[parentCgroupID] = pe.info
							r.logger.Info("Including network-parent container for cgroup attachment",
								zap.String("parent", pe.info.Name),
								zap.String("child", entry.info.Name),
								zap.Uint64("parentCgroupID", parentCgroupID))
							break
						}
					}
				}
			}
		}
	}

	r.mu.Lock()
	r.byCgroupID = updated
	r.lastRefresh = time.Now()
	r.mu.Unlock()
}

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
}

type dockerContainerInspect struct {
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
}

type containerInspectResult struct {
	Pid         int
	NetworkMode string
}

func (r *Resolver) inspectContainer(ctx context.Context, containerID string) (containerInspectResult, error) {
	url := fmt.Sprintf("http://unix/containers/%s/json", containerID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return containerInspectResult{}, err
	}

	response, err := r.client.Do(request)
	if err != nil {
		return containerInspectResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return containerInspectResult{}, fmt.Errorf("unexpected status %d", response.StatusCode)
	}

	var inspect dockerContainerInspect
	if err := json.NewDecoder(response.Body).Decode(&inspect); err != nil {
		return containerInspectResult{}, err
	}

	return containerInspectResult{
		Pid:         inspect.State.Pid,
		NetworkMode: inspect.HostConfig.NetworkMode,
	}, nil
}

func readCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}

	return "", fmt.Errorf("cgroup v2 entry not found")
}

func cgroupFullPath(cgroupPath string) string {
	return filepath.Join("/sys/fs/cgroup", cgroupPath)
}

func cgroupIDFromFullPath(fullPath string) (uint64, error) {
	info, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported stat type")
	}
	return stat.Ino, nil
}
