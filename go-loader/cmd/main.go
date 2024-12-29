package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	// _, err := xpdRunner.GetMap("ipv4_connection_tracker")
	// checkIfErrorAndExit(err)
	return 0
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
