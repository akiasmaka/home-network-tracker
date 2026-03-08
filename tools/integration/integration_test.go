package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	productImage     = "homenetworktracker:latest"
	productContainer = "hnt-integration-product"
	clientContainer  = "hnt-integration-client"
	clientImage      = "alpine:3.21"
	productPort      = 5000
	directionEgress  = 2
	protoTCP         = 6
	productStartWait = 30 * time.Second
	pollJSONTimeout  = 30 * time.Second
)

type Connection struct {
	Packets   uint64         `json:"packets"`
	Bytes     uint64         `json:"bytes"`
	Saddr     string         `json:"saddr"`
	Daddr     string         `json:"addr"`
	IfIndex   uint32         `json:"ifindex"`
	IfName    string         `json:"ifname"`
	CgroupID  uint64         `json:"cgroupId"`
	Direction uint8          `json:"direction"`
	Proto     uint8          `json:"proto"`
	SHost     []string       `json:"sHost"`
	DHost     []string       `json:"dHost"`
	Container *ContainerInfo `json:"container"`
}

type ContainerInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	Pid   int    `json:"pid"`
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
			Gateway   string `json:"Gateway"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type Harness struct {
	t *testing.T

	clientInfo   dockerInspect
	clientIP     string
	cgroupID     uint64
	hostIfName   string
	hostIfIndex  uint32
	resolvedAddr []string
}

func TestContainerTrafficCaptured(t *testing.T) {
	ctx := context.Background()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	if err := ensureImageExists(ctx, productImage); err != nil {
		t.Skip(err.Error())
	}

	cleanupContainers(t)
	(&Harness{t: t}).Run()
}

func (h *Harness) Run() {
	h.startClient()
	h.startProduct()
	h.generateTraffic("example.com")

	conn := waitForConnection(h.t, h.clientIP, h.resolvedAddr, h.cgroupID)
	h.assertConnection(conn)
}

func (h *Harness) startClient() {
	startClientContainer(h.t)
	h.clientInfo = inspectContainer(h.t, clientContainer)
	h.clientIP = pickClientIP(h.t, h.clientInfo)
	h.cgroupID = resolveCgroupID(h.t, h.clientInfo.State.Pid)
	h.hostIfName, h.hostIfIndex = resolveHostVeth(h.t, clientContainer)
	h.resolvedAddr = resolveContainerIPv4s(h.t, "example.com")
}

func (h *Harness) startProduct() {
	startProductContainer(h.t)
}

func (h *Harness) generateTraffic(hostname string) {
	generateTraffic(h.t, hostname)
}

func (h *Harness) assertConnection(conn Connection) {
	if conn.Proto != protoTCP {
		h.t.Fatalf("expected proto %d, got %d", protoTCP, conn.Proto)
	}
	if conn.Direction != directionEgress {
		h.t.Fatalf("expected direction %d, got %d", directionEgress, conn.Direction)
	}
	if conn.IfIndex != h.hostIfIndex {
		h.t.Fatalf("expected ifindex %d, got %d", h.hostIfIndex, conn.IfIndex)
	}
	if conn.IfName != h.hostIfName {
		h.t.Fatalf("expected ifname %q, got %q", h.hostIfName, conn.IfName)
	}
	if conn.Packets == 0 || conn.Bytes == 0 {
		h.t.Fatalf("expected packets/bytes > 0, got packets=%d bytes=%d", conn.Packets, conn.Bytes)
	}
	assertHostsMatch(h.t, h.clientIP, conn.SHost, "sHost")
	assertHostContains(h.t, conn.DHost, "example.com", "dHost")
	assertContainerInfo(h.t, h.clientInfo, conn.Container)
}

func cleanupContainers(t *testing.T) {
	runQuiet("docker", "rm", "-f", productContainer)
	runQuiet("docker", "rm", "-f", clientContainer)
	t.Cleanup(func() {
		runQuiet("docker", "rm", "-f", clientContainer)
		runQuiet("docker", "rm", "-f", productContainer)
	})
}

func ensureImageExists(ctx context.Context, image string) error {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("missing image %s; run ./build/build.sh --all", image)
	}
	return nil
}

func startProductContainer(t *testing.T) {
	args := []string{
		"run", "-d", "--rm",
		"--name", productContainer,
		"--privileged",
		"--network", "host",
		"--pid", "host",
		"--cgroupns", "host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		productImage,
	}
	if _, err := runCommand(context.Background(), "docker", args...); err != nil {
		t.Fatalf("start product container: %v", err)
	}
	waitForHTTP(t, fmt.Sprintf("http://localhost:%d/data", productPort))
}

func startClientContainer(t *testing.T) {
	args := []string{
		"run", "-d", "--rm",
		"--name", clientContainer,
		clientImage,
		"sleep", "300",
	}
	if _, err := runCommand(context.Background(), "docker", args...); err != nil {
		t.Fatalf("start client container: %v", err)
	}
}

func generateTraffic(t *testing.T, hostname string) {
	url := fmt.Sprintf("http://%s/", hostname)
	cmd := []string{"exec", clientContainer, "sh", "-c", fmt.Sprintf("wget -qO- %s >/dev/null", url)}
	if _, err := runCommand(context.Background(), "docker", cmd...); err != nil {
		t.Fatalf("generate traffic: %v", err)
	}
}

func waitForHTTP(t *testing.T, url string) {
	deadline := time.Now().Add(productStartWait)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("product API not ready at %s", url)
}

func waitForConnection(t *testing.T, saddr string, daddrs []string, cgroupID uint64) Connection {
	deadline := time.Now().Add(pollJSONTimeout)
	var lastErr error
	daddrSet := make(map[string]struct{}, len(daddrs))
	for _, addr := range daddrs {
		if addr == "" {
			continue
		}
		daddrSet[addr] = struct{}{}
	}
	for time.Now().Before(deadline) {
		conns, err := fetchConnections()
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if conn, ok := findConnection(conns, saddr, daddrSet, cgroupID); ok {
			return conn
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("failed to fetch connections: %v", lastErr)
	}
	t.Fatalf("connection not found for saddr=%s daddrs=%v cgroupId=%d", saddr, daddrs, cgroupID)
	return Connection{}
}

func fetchConnections() ([]Connection, error) {
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/data", productPort))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var conns []Connection
	if err := json.NewDecoder(resp.Body).Decode(&conns); err != nil {
		return nil, err
	}
	return conns, nil
}

func findConnection(conns []Connection, saddr string, daddrSet map[string]struct{}, cgroupID uint64) (Connection, bool) {
	for _, conn := range conns {
		if conn.CgroupID != cgroupID {
			continue
		}
		if conn.Saddr != saddr {
			continue
		}
		if _, ok := daddrSet[conn.Daddr]; !ok {
			continue
		}
		if conn.Direction != directionEgress || conn.Proto != protoTCP {
			continue
		}
		return conn, true
	}
	return Connection{}, false
}

func inspectContainer(t *testing.T, name string) dockerInspect {
	out, err := runCommand(context.Background(), "docker", "inspect", name)
	if err != nil {
		t.Fatalf("docker inspect %s: %v", name, err)
	}
	var result []dockerInspect
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode inspect: %v", err)
	}
	if len(result) == 0 {
		t.Fatalf("inspect returned empty for %s", name)
	}
	return result[0]
}

func pickClientIP(t *testing.T, info dockerInspect) string {
	for _, netInfo := range info.NetworkSettings.Networks {
		if netInfo.IPAddress != "" {
			return netInfo.IPAddress
		}
	}
	t.Fatalf("no networks found for container")
	return ""
}

func resolveCgroupID(t *testing.T, pid int) uint64 {
	path, err := cgroupPath(pid)
	if err != nil {
		t.Fatalf("read cgroup path: %v", err)
	}
	cgroupID, err := cgroupIDFromPath(path)
	if err != nil {
		t.Fatalf("resolve cgroup id: %v", err)
	}
	return cgroupID
}

func cgroupPath(pid int) (string, error) {
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

func cgroupIDFromPath(cgroupPath string) (uint64, error) {
	fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
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

func resolveHostVeth(t *testing.T, containerName string) (string, uint32) {
	out, err := runCommand(context.Background(), "docker", "exec", containerName, "cat", "/sys/class/net/eth0/ifindex")
	if err != nil {
		t.Fatalf("read container ifindex: %v", err)
	}
	containerIfIndex, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("parse container ifindex: %v", err)
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Fatalf("read /sys/class/net: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		iflinkPath := filepath.Join("/sys/class/net", name, "iflink")
		iflink, err := readIntFile(iflinkPath)
		if err != nil {
			continue
		}
		if iflink != containerIfIndex {
			continue
		}
		ifindexPath := filepath.Join("/sys/class/net", name, "ifindex")
		ifindex, err := readUint32File(ifindexPath)
		if err != nil {
			continue
		}
		return name, ifindex
	}
	t.Fatalf("failed to find host veth for container ifindex %d", containerIfIndex)
	return "", 0
}

func resolveContainerIPv4s(t *testing.T, hostname string) []string {
	cmd := []string{"exec", clientContainer, "sh", "-c", fmt.Sprintf("nslookup -type=A %s", hostname)}
	out, err := runCommand(context.Background(), "docker", cmd...)
	if err != nil {
		t.Fatalf("resolve %s in container: %v", hostname, err)
	}
	addrs := extractIPv4s(out)
	if len(addrs) == 0 {
		t.Fatalf("no IPv4 addresses resolved for %s", hostname)
	}
	return uniqueStrings(addrs)
}

func readIntFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func readUint32File(path string) (uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func assertHostsMatch(t *testing.T, ip string, actual []string, label string) {
	if len(actual) == 0 {
		actual = []string{""}
	}
	expected := expectedHosts(t, ip)
	if !sameStringSlice(actual, expected) {
		t.Fatalf("%s mismatch for %s: expected=%v got=%v", label, ip, expected, actual)
	}
}

func expectedHosts(t *testing.T, ip string) []string {
	hosts := loadHosts(t)
	if names, ok := hosts[ip]; ok && len(names) > 0 {
		return names
	}

	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return names
	}
	return []string{""}
}

func loadHosts(t *testing.T) map[string][]string {
	file, err := os.Open("/etc/hosts")
	if err != nil {
		t.Fatalf("open /etc/hosts: %v", err)
	}
	defer file.Close()

	result := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		result[ip] = append(result[ip], fields[1:]...)
	}
	return result
}

func sameStringSlice(a, b []string) bool {
	a = normalizeSlice(a)
	b = normalizeSlice(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normalizeSlice(in []string) []string {
	out := append([]string{}, in...)
	for i, v := range out {
		out[i] = strings.TrimSpace(v)
	}
	sort.Strings(out)
	return out
}

func assertHostContains(t *testing.T, actual []string, expected string, label string) {
	for _, value := range actual {
		if strings.TrimSuffix(strings.TrimSpace(value), ".") == expected {
			return
		}
	}
	t.Fatalf("%s mismatch: expected to contain %q, got=%v", label, expected, actual)
}

func extractIPv4s(text string) []string {
	fields := strings.Fields(text)
	var addrs []string
	for _, field := range fields {
		ip := net.ParseIP(strings.TrimSpace(field))
		if ip == nil || ip.To4() == nil {
			continue
		}
		addrs = append(addrs, ip.To4().String())
	}
	return addrs
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func assertContainerInfo(t *testing.T, info dockerInspect, container *ContainerInfo) {
	if container == nil {
		t.Fatalf("expected container info, got nil")
	}
	expected := ContainerInfo{
		ID:    info.ID,
		Name:  strings.TrimPrefix(info.Name, "/"),
		Image: info.Config.Image,
		Pid:   info.State.Pid,
	}
	if *container != expected {
		t.Fatalf("container mismatch: expected=%+v got=%+v", expected, *container)
	}
}

func runQuiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	_ = cmd.Run()
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), nil
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = strings.TrimSpace(stdout.String())
	}
	if msg == "" {
		msg = err.Error()
	}
	return stdout.String(), fmt.Errorf("%s %v: %s", name, args, msg)
}
