package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	probeRunner "github.com/akiasmaka/home-network-tracker/go-loader/pkg/bpf"
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
	l, err := config.Build()
	checkIfErrorAndExit(err)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
		cancel()
	}()

	xpdRunner, err := probeRunner.NewRunner("build/xdp.bpf.o")
	checkIfErrorAndExit(err)

	err = xpdRunner.LoadProgram("xdp_count_type")
	checkIfErrorAndExit(err)

	xpdRunner.AttachProbe("xdp_count_type", "enp3s0", probeRunner.XDP)
	checkIfErrorAndExit(err)
	defer xpdRunner.Close()

	m, err := xpdRunner.GetMap("ipv4_connection_tracker")
	checkIfErrorAndExit(err)
	innerRun(ctx, m, done, l)

	return 0
}

func innerRun(ctx context.Context,
	m *bpf.BPFMap,
	done chan bool,
	l *zap.Logger) {

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ct := tracker.NewConnectionTracker(ctx, 72*time.Hour, 24*time.Hour, m, l)
	server := output.Server{Addr: "", Port: 5000, Tracker: ct}
	go server.Serve()

	for {
		select {
		case <-done:
			l.Debug("Exiting printMapData")
			return
		case <-ticker.C:
			i := m.Iterator()
			for i.Next() {
				if i.Next() == false {
					break
				}
				k := i.Key()
				kPtr := unsafe.Pointer(&k[0])
				kData, err := network.ParseIPv4Key(k)

				if err != nil {
					l.Sugar().Info("Error parsing key ", err)
					continue
				}
				l.Debug(network.IntToIPv4(kData.Saddr).String())
				v, err := m.GetValue(kPtr)
				if err != nil {
					l.Sugar().Error("Error GetValue key ", err)
					continue
				}

				//TODO: move into the connetion tracker
				s, err := tracker.ParseConnectionStats(v)
				if err != nil {
					l.Sugar().Error("Error parseConnectionStats key ", err)
					continue
				}

				var kernelKey [64]byte
				copy(kernelKey[:], k)
				ct.Store(kernelKey, tracker.Connection{
					ConnectionStats: s,
					Saddr:           network.IntToIPv4(kData.Saddr).String(),
					Daddr:           network.IntToIPv4(kData.Daddr).String(),
					Type:            network.IPV4,
				})
			}
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
