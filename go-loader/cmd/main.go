package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	probeRunner "github.com/akiasmaka/home-network-tracker/go-loader/pkg/bpf"
	bpf "github.com/aquasecurity/libbpfgo"
)

func checkIfErrorAndExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() int {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	xpdRunner, err := probeRunner.NewRunner("build/xdp.bpf.o")
	checkIfErrorAndExit(err)

	err = xpdRunner.LoadProgram("xdp_count_type")
	checkIfErrorAndExit(err)

	xpdRunner.AttachProbe("xdp_count_type", "enp3s0", probeRunner.XDP)
	checkIfErrorAndExit(err)
	defer xpdRunner.Close()

	m, err := xpdRunner.GetMap("ipv4_connection_tracker")
	printMapData(m, done)
	checkIfErrorAndExit(err)

	return 0
}

type IPv4Key struct {
	Saddr uint32
	Daddr uint32
}

type ConnectionStats struct {
	Packets uint64
	Bytes   uint64
}

func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func parseIPv4Key(key []byte) (IPv4Key, error) {
	var d IPv4Key
	r := bytes.NewReader(key)
	err := binary.Read(r, binary.BigEndian, &d)
	return d, err
}

func parseConnectionStats(stats []byte) (ConnectionStats, error) {
	var d ConnectionStats
	r := bytes.NewReader(stats)
	err := binary.Read(r, binary.NativeEndian, &d)
	return d, err
}

// eventually grab all keys available, batch grab data print then delete?
func printMapData(m *bpf.BPFMap, done chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-done:
			fmt.Println("Exit received")
			return
		case <-ticker.C:
			i := m.Iterator()
			for i.Next() {
				if i.Next() == false {
					break
				}
				k := i.Key()
				kPtr := unsafe.Pointer(&k[0])
				kData, err := parseIPv4Key(k)
				if err != nil {
					fmt.Println("Error parsing key ", err)
					continue
				}
				fmt.Println("------")
				fmt.Println(IntToIPv4(kData.Saddr).String())
				v, err := m.GetValue(kPtr)
				if err != nil {
					fmt.Println("Error GetValue key ", err)
					continue
				}
				s, err := parseConnectionStats(v)
				if err != nil {
					fmt.Println("Error parseConnectionStats key ", err)
					continue
				}
				fmt.Println("Total packets: ", s.Packets)
				fmt.Println("Total Bytes: ", s.Bytes)
				fmt.Println("------")
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
