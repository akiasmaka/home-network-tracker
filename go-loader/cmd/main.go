package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	probeRunner "github.com/akiasmaka/home-network-tracker/go-loader/pkg/bpf"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/containermeta"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/history"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/network"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/output"
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
	bpf "github.com/aquasecurity/libbpfgo"
	"go.uber.org/zap"
)

func checkIfErrorAndExit(err error) {
	if err != nil {
		panic(err)
	}
}

func run() int {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	config.DisableStacktrace = true
	l, err := config.Build()
	checkIfErrorAndExit(err)

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			if level <= bpf.LibbpfWarnLevel {
				fmt.Fprint(os.Stderr, msg)
			}
		},
		LogFilters: []func(libLevel int, msg string) bool{
			func(libLevel int, msg string) bool {
				return libLevel > bpf.LibbpfWarnLevel
			},
		},
	})

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	xpdRunner, err := probeRunner.NewRunner("build/xdp.bpf.o")
	checkIfErrorAndExit(err)

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			xpdRunner.Close()
		})
	}

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		cleanup()
		done <- true
		cancel()
	}()

	mV4, err := xpdRunner.GetMap("ipv4_connection_tracker")
	checkIfErrorAndExit(err)

	mV6, err := xpdRunner.GetMap("ipv6_connection_tracker")
	checkIfErrorAndExit(err)

	ifaces, err := discoverInterfaces()
	checkIfErrorAndExit(err)
	if len(ifaces) == 0 {
		checkIfErrorAndExit(fmt.Errorf("no eligible interfaces found"))
	}

	ifaceNames := buildInterfaceNameMap(ifaces)
	ifaceNameList := buildInterfaceNameList(ifaces)
	dnsBpfPath := "build/dns_sniffer.bpf.o"
	ct := tracker.NewConnectionTracker(ctx, 72*time.Hour, 1*time.Hour, mV4, mV6, ifaceNameList, dnsBpfPath, l)

	historyPath := os.Getenv("HISTORY_PATH")
	if historyPath == "" {
		historyPath = "/history/history.db"
	}
	historyStore, err := history.NewHistoryStore(historyPath, 7*24*time.Hour, 1*time.Second, l)
	checkIfErrorAndExit(err)
	defer historyStore.Close()

	// Seed tracker from persisted connections (preserving timestamps).
	entries, keys, loadErr := historyStore.LoadConnections()
	if loadErr != nil {
		l.Sugar().Warnf("Failed to load connections: %v", loadErr)
	} else if len(entries) > 0 {
		ct.SeedEntries(entries, keys)
		l.Sugar().Infof("Seeded %d connections from history database", len(entries))
	}

	if err := historyStore.TakeSnapshot(ct); err != nil {
		l.Sugar().Warnf("Failed to take initial snapshot: %v", err)
	}
	historyStore.StartSnapshotTicker(ctx, ct)

	err = xpdRunner.LoadProgram("cgroup_count_ingress")
	checkIfErrorAndExit(err)
	err = xpdRunner.LoadProgram("cgroup_count_egress")
	checkIfErrorAndExit(err)

	if ct.ContainerResolver() == nil {
		cgroupPath, err := cgroupRootPath()
		checkIfErrorAndExit(err)
		checkIfErrorAndExit(xpdRunner.AttachCgroup("cgroup_count_ingress", cgroupPath))
		checkIfErrorAndExit(xpdRunner.AttachCgroup("cgroup_count_egress", cgroupPath))
	} else {
		go attachContainerPrograms(ctx, xpdRunner, ct.ContainerResolver(), l)
	}
	defer cleanup()

	innerRun(ctx, mV4, mV6, ct, historyStore, ifaceNames, done, l)

	return 0
}

func cgroupRootPath() (string, error) {
	const path = "/sys/fs/cgroup"
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

func innerRun(ctx context.Context,
	mV4 *bpf.BPFMap,
	mV6 *bpf.BPFMap,
	ct *tracker.ConnectionTracker,
	historyStore *history.HistoryStore,
	ifaceNames map[uint32]string,
	done chan bool,
	l *zap.Logger) {

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	server := output.Server{Addr: "", Port: 5000, Tracker: ct, History: historyStore, Logger: l}
	go server.Serve()

	for {
		select {
		case <-done:
			l.Debug("Exiting printMapData")
			return
		case <-ticker.C:
			processIPv4Map(mV4, ct, ifaceNames, l)
			processIPv6Map(mV6, ct, ifaceNames, l)
		}
	}
}

type cgroupAttacher interface {
	AttachCgroup(programName, cgroupPath string) error
}

func attachContainerPrograms(ctx context.Context,
	runner cgroupAttacher,
	resolver *containermeta.Resolver,
	l *zap.Logger) {
	if resolver == nil || runner == nil {
		return
	}

	attached := make(map[string]struct{})
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolver.RefreshIfStale(ctx, 5*time.Second)
			for _, container := range resolver.Snapshot() {
				if container.CgroupPath == "" {
					l.Sugar().Warnf("Container %s (%s) has empty cgroup path, skipping", container.Name, container.ID)
					continue
				}
				if _, ok := attached[container.CgroupPath]; ok {
					continue
				}
				if err := runner.AttachCgroup("cgroup_count_ingress", container.CgroupPath); err != nil {
					l.Sugar().Warnf("Failed to attach ingress cgroup program to container %s (path=%s): %v", container.Name, container.CgroupPath, err)
					continue
				}
				if err := runner.AttachCgroup("cgroup_count_egress", container.CgroupPath); err != nil {
					l.Sugar().Warnf("Failed to attach egress cgroup program to container %s (path=%s): %v", container.Name, container.CgroupPath, err)
					continue
				}
				attached[container.CgroupPath] = struct{}{}
				l.Sugar().Infof("Attached cgroup programs to container %s (%s)", container.Name, container.CgroupPath)
			}
		}
	}
}

func processIPv4Map(m *bpf.BPFMap, ct *tracker.ConnectionTracker, ifaceNames map[uint32]string, l *zap.Logger) {
	if m == nil {
		return
	}

	i := m.Iterator()
	keysToDelete := make([][64]byte, 0, 256)
	for i.Next() {
		k := i.Key()
		kPtr := unsafe.Pointer(&k[0])
		kData, err := network.ParseIPv4Key(k)
		if err != nil {
			l.Sugar().Info("Error parsing IPv4 key ", err)
			continue
		}

		v, err := m.GetValue(kPtr)
		if err != nil {
			l.Sugar().Error("Error GetValue IPv4 key ", err)
			continue
		}

		s, err := tracker.ParseConnectionStats(v)
		if err != nil {
			l.Sugar().Error("Error parseConnectionStats IPv4 ", err)
			continue
		}

		var fullKey [64]byte
		copy(fullKey[:], k)
		normalizedKey, err := network.NormalizeKernelKey(k, network.IPV4)
		if err != nil {
			l.Sugar().Error("Error normalizing IPv4 key ", err)
			continue
		}
		containerInfo := ct.ResolveContainer(kData.CgroupID)

		// Zero unresolvable ifindex in key to prevent entry fragmentation
		// from container-internal interfaces the host can't map.
		ifName := ifaceNames[kData.IfIndex]
		ifIndex := kData.IfIndex
		if ifName == "" {
			ifIndex = 0
			binary.LittleEndian.PutUint32(normalizedKey[8:12], 0)
		}

		ct.Store(normalizedKey, tracker.Connection{
			ConnectionStats: s,
			Saddr:           network.IntToIPv4(kData.Saddr).String(),
			Daddr:           network.IntToIPv4(kData.Daddr).String(),
			IfIndex:         ifIndex,
			IfName:          ifName,
			CgroupID:        kData.CgroupID,
			Direction:       kData.Direction,
			Proto:           kData.Proto,
			Container:       containerInfo,
			Type:            network.IPV4,
		})
		keysToDelete = append(keysToDelete, fullKey)
	}

	for i := range keysToDelete {
		key := keysToDelete[i]
		if err := m.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			l.Debug("Failed to delete IPv4 kernel map key", zap.Error(err))
		}
	}
}

func processIPv6Map(m *bpf.BPFMap, ct *tracker.ConnectionTracker, ifaceNames map[uint32]string, l *zap.Logger) {
	if m == nil {
		return
	}

	i := m.Iterator()
	keysToDelete := make([][64]byte, 0, 256)
	for i.Next() {
		k := i.Key()
		kPtr := unsafe.Pointer(&k[0])
		kData, err := network.ParseIPv6Key(k)
		if err != nil {
			l.Sugar().Info("Error parsing IPv6 key ", err)
			continue
		}

		v, err := m.GetValue(kPtr)
		if err != nil {
			l.Sugar().Error("Error GetValue IPv6 key ", err)
			continue
		}

		s, err := tracker.ParseConnectionStats(v)
		if err != nil {
			l.Sugar().Error("Error parseConnectionStats IPv6 ", err)
			continue
		}

		var fullKey [64]byte
		copy(fullKey[:], k)
		normalizedKey, err := network.NormalizeKernelKey(k, network.IPV6)
		if err != nil {
			l.Sugar().Error("Error normalizing IPv6 key ", err)
			continue
		}
		containerInfo := ct.ResolveContainer(kData.CgroupID)

		// Zero unresolvable ifindex in key to prevent entry fragmentation
		// from container-internal interfaces the host can't map.
		ifName := ifaceNames[kData.IfIndex]
		ifIndex := kData.IfIndex
		if ifName == "" {
			ifIndex = 0
			binary.LittleEndian.PutUint32(normalizedKey[32:36], 0)
		}

		ct.Store(normalizedKey, tracker.Connection{
			ConnectionStats: s,
			Saddr:           net.IP(kData.Saddr.Addr[:]).String(),
			Daddr:           net.IP(kData.Daddr.Addr[:]).String(),
			IfIndex:         ifIndex,
			IfName:          ifName,
			CgroupID:        kData.CgroupID,
			Direction:       kData.Direction,
			Proto:           kData.Proto,
			Container:       containerInfo,
			Type:            network.IPV6,
		})
		keysToDelete = append(keysToDelete, fullKey)
	}

	for i := range keysToDelete {
		key := keysToDelete[i]
		if err := m.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			l.Debug("Failed to delete IPv6 kernel map key", zap.Error(err))
		}
	}
}

func listenToEvents(rb *bpf.RingBuffer, eventsChannel chan []byte, done chan bool) int {
	rb.Poll(300)
	defer rb.Stop()
	for {
		select {
		case eventBytes := <-eventsChannel:
			fmt.Println(eventBytes)
		case <-done:
			fmt.Println("Exit received")
			return 0
		}
	}
}

func main() {
	os.Exit(run())
}

func discoverInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ifaces := make([]net.Interface, 0, len(all))
	for _, iface := range all {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaces = append(ifaces, iface)
	}

	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Index < ifaces[j].Index
	})

	return ifaces, nil
}

func buildInterfaceNameMap(ifaces []net.Interface) map[uint32]string {
	mapping := make(map[uint32]string, len(ifaces))
	for _, iface := range ifaces {
		mapping[uint32(iface.Index)] = iface.Name
	}
	return mapping
}

func buildInterfaceNameList(ifaces []net.Interface) []string {
	list := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		list = append(list, iface.Name)
	}
	return list
}
