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
	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
	bpf "github.com/aquasecurity/libbpfgo"
	"go.uber.org/zap"
)

func checkIfErrorAndExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() int {
	l, _ := zap.NewDevelopment()
	l.Info("Starting up")
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
	printMapData(ctx, m, done, l)
	checkIfErrorAndExit(err)

	return 0
}

// TODO/NOTES: periodically query the map for new "keys" (basically new connections)
// store the keys in a slice? then batch grab the values every x?
// eventually remove the entries from the bpf map & slice if they havent' been updated in a while?
// cleanup might not be necessary?
// before removing store them in a ondisk database or something? or throw them in a database immediately?
// prometheus?
func printMapData(ctx context.Context,
	m *bpf.BPFMap,
	done chan bool,
	l *zap.Logger) {

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ct := tracker.NewConnectionTracker(ctx, 10*time.Second, 5*time.Second, 10240, m, l)

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
				l.Info("------")
				l.Info(network.IntToIPv4(kData.Saddr).String())
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
				l.Sugar().Info("Total packets: ", s.Packets)
				l.Sugar().Info("Total Bytes: ", s.Bytes)
				l.Info("------")
				var kernelKey [64]byte
				copy(kernelKey[:], k)
				ct.Store(tracker.ConnectionKey{Key: kData, KernelKey: kernelKey}, s)
			}
		}
	}
}

// takes a BPF_MAP_TYPE_RINGBUF and grabs events from it
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
